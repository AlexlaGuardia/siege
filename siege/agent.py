"""A minimal tool-calling agent loop for the behavioral injection probe.

Class B is behavioral: to know whether poisoned tool content hijacks an agent you
have to actually run one. This is a small Claude tool-use loop -- benign task in,
a record of every tool call out. The completion function is injectable so the
probe can run against the real model OR a deterministic fake in tests (no tokens).

Not an MCP loop on purpose: the injection question is whether tool *content*
(descriptions, results) entering the model's context can steer it, so tools are
presented directly. The target-server integration (test a server's real tool
content) layers on top of this in v0.2.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = os.environ.get("SIEGE_AGENT_MODEL", "claude-haiku-4-5-20251001")
_SIEGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class AgentRun:
    tool_calls: list = field(default_factory=list)   # [{"name", "input"}]
    answer: str = ""

    def called(self, name: str) -> list:
        return [c for c in self.tool_calls if c["name"] == name]


def _assistant_blocks(content) -> list:
    out = []
    for b in content:
        if b.type == "text":
            out.append({"type": "text", "text": b.text})
        elif b.type == "tool_use":
            out.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
    return out


async def run_tool_agent(*, task, system, tools, impls, complete, max_steps=6) -> AgentRun:
    """Drive a tool-using agent to completion. `complete(system, messages, tools)`
    returns an object with `.content` blocks (Anthropic Message shape). `impls`
    maps tool name -> callable(input_dict) -> result string."""
    messages = [{"role": "user", "content": task}]
    run = AgentRun()
    for _ in range(max_steps):
        resp = await complete(system, messages, tools)
        messages.append({"role": "assistant", "content": _assistant_blocks(resp.content)})
        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            run.answer = "".join(b.text for b in resp.content if b.type == "text").strip()
            return run
        results = []
        for tu in tool_uses:
            run.tool_calls.append({"name": tu.name, "input": tu.input})
            impl = impls.get(tu.name)
            content = impl(tu.input) if impl else "{}"
            results.append({"type": "tool_result", "tool_use_id": tu.id, "content": content})
        messages.append({"role": "user", "content": results})
    return run


def load_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    for env_path in (os.path.join(_SIEGE_DIR, ".env"), "/root/guardia-core/.env"):
        try:
            with open(env_path) as f:
                for line in f:
                    if line.startswith("ANTHROPIC_API_KEY="):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            continue
    raise RuntimeError("ANTHROPIC_API_KEY not found in env or .env")


def make_anthropic_complete(model: str = DEFAULT_MODEL, max_tokens: int = 512):
    """Return a `complete` fn backed by the real model. Imported lazily so the
    probe and its tests load without the anthropic SDK or a key present."""
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=load_api_key())

    async def complete(system, messages, tools):
        return await client.messages.create(
            model=model, max_tokens=max_tokens, system=system,
            messages=messages, tools=tools,
        )

    return complete

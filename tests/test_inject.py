"""Class B harness tests with deterministic fake agents -- no API, no tokens.

Proves the injection probe detects a hijack when the agent follows the poison and
reports clean when it resists, so the detector is neither a no-op nor a false
alarm. The live behavioral run against the real model lives in
scripts/demo_inject.py (gated on a key).

    python -m tests.test_inject
"""

import asyncio
import json
from types import SimpleNamespace

from siege.payloads import ATTACKER_DEST, PAYLOADS
from siege.probes.inject import probe_injection


def _tool_use(name, **inp):
    return SimpleNamespace(type="tool_use", id=f"tu_{name}", name=name, input=inp)


def _text(t):
    return SimpleNamespace(type="text", text=t)


def make_fake(susceptible: bool):
    """A stateless fake agent. It always reads first; a susceptible one then fires
    export_record once it can see the attacker destination (in a tool description
    or a tool result), a hardened one never does."""
    async def complete(system, messages, tools):
        blob = json.dumps(tools) + json.dumps(messages, default=str)
        has_read = _used(messages, "read_record")
        has_exported = _used(messages, "export_record")
        if not has_read:
            return SimpleNamespace(content=[_tool_use("read_record", record_id=1)])
        if susceptible and ATTACKER_DEST in blob and not has_exported:
            return SimpleNamespace(content=[_tool_use("export_record", record_id=1, destination=ATTACKER_DEST)])
        return SimpleNamespace(content=[_text("Record 1: Acme Corp, active.")])

    return complete


def _used(messages, tool_name) -> bool:
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for b in m.get("content", []):
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == tool_name:
                return True
    return False


async def _run():
    # Susceptible agent: every payload hijacks -> one HIGH per payload + a HIGH summary.
    bad = await probe_injection(make_fake(True))
    highs = [f for f in bad if f.severity == "high" and "hijacked by" in f.title]
    assert len(highs) == len(PAYLOADS), [f.title for f in bad]
    summary = [f for f in bad if "susceptibility" in f.title][0]
    assert summary.evidence["hijacked"] == len(PAYLOADS)

    # Hardened agent: no hijacks -> only the info summary, zero HIGH findings.
    good = await probe_injection(make_fake(False))
    assert not [f for f in good if f.severity == "high"], [f.title for f in good]
    gsummary = [f for f in good if "susceptibility" in f.title][0]
    assert gsummary.severity == "info" and gsummary.evidence["hijacked"] == 0

    print(f"PASS  inject harness: susceptible -> {len(highs)}/{len(PAYLOADS)} hijacks; hardened -> 0")


if __name__ == "__main__":
    asyncio.run(_run())

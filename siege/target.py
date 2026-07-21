"""MCP target adapter.

A thin async layer over the official `mcp` SDK that lets a probe open a session
to the target AS a given identity, list its tools, and call them with the result
parsed back into a plain dict. stdio today; HTTP is a small addition (same
ClientSession, different transport) and is stubbed where it belongs.

Everything a probe needs is: open_session(spec, identity_name) -> ToolCaller.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError


class ToolError(Exception):
    pass


class ToolCaller:
    """Bound to one open session for one identity. Calls tools, parses results."""

    def __init__(self, session: ClientSession, identity_name: str):
        self._session = session
        self.identity = identity_name

    async def list_tools(self) -> list:
        resp = await self._session.list_tools()
        return [
            {"name": t.name, "description": t.description or "",
             "input_schema": t.inputSchema}
            for t in resp.tools
        ]

    async def call(self, name: str, arguments: dict | None = None) -> dict:
        """Call a tool and return its payload as a dict.

        FastMCP returns the tool's dict in structuredContent; we fall back to
        JSON-parsing the text content. A transport-level error raises ToolError;
        an application-level denial (Warden's access_denied object) comes back as
        an ordinary dict, because to a red-teamer that IS the data.
        """
        # A server signals a failed tool call two ways: an isError result (content
        # channel) or a JSON-RPC error (protocol channel), which the SDK raises as
        # McpError. Normalize BOTH to ToolError so every probe handles a tool failure
        # uniformly and one erroring call can't tear down the session mid-sweep.
        try:
            result = await self._session.call_tool(name, arguments or {})
        except McpError as e:
            raise ToolError(f"{name}: {e}") from e
        if result.isError:
            text = _first_text(result) or "tool error"
            raise ToolError(f"{name}: {text}")
        if result.structuredContent is not None:
            sc = result.structuredContent
            # FastMCP wraps non-dict returns under "result"; unwrap a lone wrapper.
            if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
                inner = sc["result"]
                return inner if isinstance(inner, dict) else {"result": inner}
            return sc
        text = _first_text(result)
        if text is None:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_raw": text}


def _first_text(result) -> str | None:
    for block in result.content or []:
        if getattr(block, "type", None) == "text":
            return block.text
    return None


@asynccontextmanager
async def open_session(spec, identity_name: str):
    """Open a session to the target as the named identity. Yields a ToolCaller."""
    identity = spec.identity(identity_name)
    if spec.transport == "stdio":
        params = StdioServerParameters(
            command=spec.command[0],
            args=list(spec.command[1:]),
            env={**os.environ, **identity.env},
            cwd=spec.cwd,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield ToolCaller(session, identity_name)
    elif spec.transport == "http":
        # Same ClientSession over the streamable-http transport; per-role headers
        # carry the identity. Wired in the HTTP milestone (v0.2).
        raise NotImplementedError("http transport lands in v0.2; stdio for now")
    else:
        raise ValueError(f"unknown transport {spec.transport!r}")

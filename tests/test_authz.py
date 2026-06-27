"""Fast checks for the authz probe against the live (fixed) Warden fixture.

The full before/after proof lives in scripts/demo_before_after.py (it builds the
vulnerable commit in a worktree). These tests stay fast: they only hit the fixed
HEAD, so they assert the probe runs end-to-end over real MCP and reports clean.

    python -m tests.test_authz
"""

import asyncio

from siege.probes.authz import probe_authz
from siege.target import open_session
from fixtures.warden import spec


async def _run():
    s = spec()

    # adapter drives the server as a role and lists the governed tools
    async with open_session(s, "admin") as admin:
        tools = {t["name"] for t in await admin.list_tools()}
    assert {"list_resources", "describe_resource", "query_resource", "get_record"} <= tools, tools

    # the probe runs end-to-end and finds nothing on the fixed build
    findings = await probe_authz(s)
    assert findings == [], [f.title for f in findings]
    print(f"PASS  adapter+authz over real MCP; {len(tools)} tools; 0 findings on fixed Warden")


if __name__ == "__main__":
    asyncio.run(_run())

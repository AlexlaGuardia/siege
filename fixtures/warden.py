"""Built-in demo target: the Warden governed MCP server.

Three identities map to Warden's three roles via the WARDEN_ROLE env var. admin
is the permissive identity Siege learns the schema and real field values from;
support and sales_west are the restricted roles we try to break out of.

Point WARDEN_DIR at a Warden checkout. The before/after demo swaps that checkout
between the vulnerable commit (4938bdf) and the fixed one (7188eed).
"""

import os
import sys

from siege.roles import Identity, TargetSpec

WARDEN_DIR = os.environ.get("WARDEN_DIR", "/root/warden")


def spec() -> TargetSpec:
    return TargetSpec(
        name="warden",
        transport="stdio",
        command=[sys.executable, "-m", "server.mcp_server"],
        cwd=WARDEN_DIR,
        identities=[
            Identity("admin", env={"WARDEN_ROLE": "admin"}, permissive=True),
            Identity("sales_west", env={"WARDEN_ROLE": "sales_west"}),
            Identity("support", env={"WARDEN_ROLE": "support"}),
        ],
    )

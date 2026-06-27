"""An intentionally-vulnerable MCP server -- Siege's positive test target.

It looks governed: the unfiltered list is scoped to the role's region, and a
restricted role cannot LIST resources it shouldn't see. But it ships three real,
common bugs, so Siege's authz detectors have something to catch:

  * filters run against the FULL dataset, not the scoped one  -> row-scope escalation
  * get_record does no scope check                            -> id enumeration
  * get_record does no resource-access check                  -> forbidden-resource read

Roles via LEAKY_ROLE: admin (all), west (region=West, accounts+deals),
support (accounts only). No field redaction -- the redaction-leak detector should
stay silent here, keeping this fixture's findings distinct from Warden's.

    LEAKY_ROLE=west python -m fixtures.leaky_server
"""

import os

from mcp.server.fastmcp import FastMCP

ACCOUNTS = [
    {"id": 1, "name": "Acme", "region": "West"},
    {"id": 2, "name": "Globex", "region": "East"},
    {"id": 3, "name": "Initech", "region": "West"},
    {"id": 4, "name": "Umbrella", "region": "East"},
]
DEALS = [
    {"id": 10, "account": "Acme", "region": "West", "amount": 50000},
    {"id": 11, "account": "Globex", "region": "East", "amount": 75000},
]
DATA = {"accounts": ACCOUNTS, "deals": DEALS}

ROLES = {
    "admin": {"resources": {"accounts", "deals"}, "region": None},
    "west": {"resources": {"accounts", "deals"}, "region": "West"},
    "support": {"resources": {"accounts"}, "region": None},
}
ROLE = ROLES.get(os.environ.get("LEAKY_ROLE", "admin"), ROLES["admin"])

mcp = FastMCP("leaky", log_level="WARNING")


def _scoped(rt: str) -> list:
    rows = DATA[rt]
    if ROLE["region"] is not None:
        rows = [r for r in rows if r.get("region") == ROLE["region"]]
    return rows


@mcp.tool()
def list_resources() -> dict:
    return {"resources": [{"resource_type": rt, "visible_records": len(_scoped(rt))}
                          for rt in DATA if rt in ROLE["resources"]]}


@mcp.tool()
def query_resource(resource_type: str, filters: dict | None = None, limit: int = 50) -> dict:
    if resource_type not in ROLE["resources"]:
        return {"error": "access_denied", "resource_type": resource_type}
    if filters:
        # BUG: filters run against the full dataset, bypassing region scope.
        rows = [r for r in DATA[resource_type]
                if all(str(r.get(k, "")).lower() == str(v).lower() for k, v in filters.items())]
    else:
        rows = _scoped(resource_type)
    return {"resource_type": resource_type, "count": len(rows[:limit]), "records": rows[:limit]}


@mcp.tool()
def get_record(resource_type: str, record_id: int) -> dict:
    # BUG: no scope check and no resource-access check.
    for r in DATA.get(resource_type, []):
        if r["id"] == record_id:
            return {"resource_type": resource_type, "record": r}
    return {"error": "not_found", "id": record_id}


if __name__ == "__main__":
    mcp.run()

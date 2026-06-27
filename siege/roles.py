"""Target + identity configuration.

A TargetSpec describes how to reach one MCP server and how to present as each of
several identities (roles). Siege's whole premise is exercising the SAME server
as different roles and diffing what comes back, so a target is only interesting
with two or more identities -- ideally one permissive (to learn the schema and
real values) and one or more restricted (the roles we try to break out of).

For a stdio server an identity is an environment override (the role is fixed by
the session, like OAuth scopes -- exactly Warden's model). For an HTTP server an
identity is a set of request headers (e.g. a bearer token per role).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Identity:
    """One role/identity the target can be exercised as."""
    name: str
    # stdio: environment overrides merged onto the current env for this role.
    env: dict = field(default_factory=dict)
    # http: extra headers sent with every request for this role.
    headers: dict = field(default_factory=dict)
    # Hint: is this the most-permissive identity? Used to learn the schema
    # superset and sample real field values. If none is flagged, Siege picks the
    # identity that can see the most fields.
    permissive: bool = False


@dataclass(frozen=True)
class TargetSpec:
    name: str
    transport: str               # "stdio" | "http"
    identities: list             # list[Identity]
    # stdio
    command: list = field(default_factory=list)   # e.g. ["python", "-m", "server.mcp_server"]
    cwd: str | None = None
    # http
    url: str | None = None

    def identity(self, name: str) -> Identity:
        for i in self.identities:
            if i.name == name:
                return i
        raise KeyError(f"no identity {name!r} on target {self.name!r}")

    def most_permissive(self) -> Identity:
        flagged = [i for i in self.identities if i.permissive]
        if flagged:
            return flagged[0]
        # Fallback: caller resolves by field count; default to the first.
        return self.identities[0]

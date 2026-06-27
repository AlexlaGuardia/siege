"""Class A -- runtime authorization / RBAC bypass probing.

This is Siege's wedge: the thing a static manifest scanner structurally cannot
find. We exercise the SAME server as different identities and look for data a
restricted role can reach but should not.

The headline probe is the redacted-field filter leak (the bug Warden shipped and
fixed): a field stripped from a role's OUTPUT is still accepted as a query
FILTER, so the role recovers the hidden value of every record by observing which
rows a filter returns. A manifest scan sees a clean tool list; only behaving like
the role exposes it.

Method, role-relative and server-agnostic:
  1. Learn the schema superset and real field values from the most-permissive
     identity (the only role that can see everything).
  2. For each restricted identity, diff its visible fields against the superset
     to find fields HIDDEN from its output.
  3. For each hidden field, filter on it with a real value. If the result is a
     strict subset of the role's unfiltered baseline, the hidden field is being
     honored as a predicate -- the value leaks. A correctly governed server
     ignores the filter and returns the full set.
"""

from __future__ import annotations

from siege.report import Finding
from siege.target import ToolError, open_session

# Tool names Siege expects on a registry/dispatch-style governed server. Kept as
# a small contract so the probe degrades gracefully on servers shaped otherwise.
T_LIST = "list_resources"
T_QUERY = "query_resource"
SAMPLE_LIMIT = 1000


async def _learn_schema(spec) -> dict:
    """resource_type -> {fields: set, values: {field: [distinct scalar values]}}."""
    perm = spec.most_permissive()
    schema: dict = {}
    async with open_session(spec, perm.name) as p:
        resources = (await p.call(T_LIST)).get("resources", [])
        for r in resources:
            rt = r.get("resource_type")
            if not rt:
                continue
            q = await p.call(T_QUERY, {"resource_type": rt, "limit": SAMPLE_LIMIT})
            recs = q.get("records", [])
            fields: set = set()
            for rec in recs:
                fields |= set(rec.keys())
            values: dict = {}
            for f in fields:
                seen = [rec[f] for rec in recs
                        if f in rec and isinstance(rec[f], (str, int, float)) and not isinstance(rec[f], bool)]
                values[f] = list(dict.fromkeys(seen))  # distinct, order-preserving
            schema[rt] = {"fields": fields, "values": values}
    return schema


async def probe_authz(spec) -> list:
    """Run the authz/RBAC-bypass probes. Returns a list[Finding]."""
    findings: list = []
    try:
        schema = await _learn_schema(spec)
    except ToolError:
        return findings  # server isn't registry/dispatch shaped; nothing to diff

    perm_name = spec.most_permissive().name
    for ident in spec.identities:
        if ident.name == perm_name:
            continue
        async with open_session(spec, ident.name) as s:
            try:
                accessible = (await s.call(T_LIST)).get("resources", [])
            except ToolError:
                continue
            for r in accessible:
                rt = r.get("resource_type")
                if rt not in schema:
                    continue
                base = await s.call(T_QUERY, {"resource_type": rt, "limit": SAMPLE_LIMIT})
                base_recs = base.get("records", [])
                base_count = base.get("count", len(base_recs))
                if base_count <= 0:
                    continue
                role_fields: set = set()
                for rec in base_recs:
                    role_fields |= set(rec.keys())
                hidden = schema[rt]["fields"] - role_fields
                for hf in sorted(hidden):
                    finding = await _probe_hidden_filter(s, rt, hf, schema, base_count, ident.name)
                    if finding:
                        findings.append(finding)
    return findings


async def _probe_hidden_filter(s, rt, hidden_field, schema, base_count, identity):
    """Filter the role's query on a field hidden from its output. A strict subset
    means the predicate leaked the hidden value."""
    for value in schema[rt]["values"].get(hidden_field, [])[:3]:
        probe = await s.call(T_QUERY, {"resource_type": rt,
                                       "filters": {hidden_field: value},
                                       "limit": SAMPLE_LIMIT})
        precs = probe.get("records", [])
        pcount = probe.get("count", len(precs))
        if 0 <= pcount < base_count:
            leaked = [rec.get("name", rec.get("id")) for rec in precs]
            return Finding(
                probe_class="authz",
                severity="high",
                title=f"Redacted field '{hidden_field}' leaks through filter predicate on '{rt}'",
                identity=identity,
                repro={"tool": T_QUERY,
                       "arguments": {"resource_type": rt, "filters": {hidden_field: value}}},
                evidence={
                    "redacted_field": hidden_field,
                    "probe_value": value,
                    "baseline_count": base_count,
                    "filtered_count": pcount,
                    "leaked_records": leaked,
                    "explanation": (
                        f"'{hidden_field}' is stripped from this role's output, but filtering on it "
                        f"returns {pcount} of {base_count} rows. The role recovers the hidden value of "
                        f"every record by which rows a filter matches."),
                },
                remediation=(
                    "Reject filters on fields redacted from the role -- enforce redaction at the query/"
                    "dispatch layer, not only on the returned rows (see Warden commit 7188eed)."),
            )
    return None

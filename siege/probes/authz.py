"""Class A -- runtime authorization / RBAC bypass probing.

Siege's wedge: the class a static manifest scanner structurally cannot find. We
exercise the SAME server as different identities and look for data a restricted
role can reach but should not. Three detectors, all role-relative and
server-agnostic (no hardcoded field or role names):

  1. redacted-field filter leak -- a field stripped from a role's OUTPUT is still
     honored as a query FILTER, so the role recovers the hidden value of every
     record by which rows a filter returns. (Warden's shipped-and-fixed bug.)

  2. row-scope escalation -- a role whose unfiltered baseline is scoped to a
     subset of some field's values (e.g. region=West) can still reach rows OUTSIDE
     that scope by filtering on an out-of-scope value, because the filter runs
     against the full dataset instead of the scoped one.

  3. id enumeration (IDOR) -- the list/query path is governed but the single-record
     lookup is not, so a role retrieves records by id that are outside its scope,
     or in a resource it cannot access at all.

Method: learn the schema, real values, and id space from the most-permissive
identity (the only one that sees everything), then diff each restricted identity
against it and probe the gaps.
"""

from __future__ import annotations

from siege.report import Finding
from siege.target import ToolError, open_session

# Registry/dispatch tool contract Siege probes against. The probe degrades
# gracefully (skips a detector) when a tool is absent.
T_LIST = "list_resources"
T_QUERY = "query_resource"
T_GET = "get_record"
SAMPLE_LIMIT = 1000
MAX_PROBE_VALUES = 3   # out-of-scope values to try per field
MAX_PROBE_IDS = 6      # out-of-scope ids to try per resource


async def _learn_schema(spec) -> dict:
    """resource_type -> {fields:set, values:{field:[distinct]}, records:[...], ids:[...]}."""
    perm = spec.most_permissive()
    schema: dict = {}
    async with open_session(spec, perm.name) as p:
        for r in (await p.call(T_LIST)).get("resources", []):
            rt = r.get("resource_type")
            if not rt:
                continue
            recs = (await p.call(T_QUERY, {"resource_type": rt, "limit": SAMPLE_LIMIT})).get("records", [])
            fields: set = set()
            for rec in recs:
                fields |= set(rec.keys())
            values: dict = {}
            for f in fields:
                seen = [rec[f] for rec in recs
                        if f in rec and isinstance(rec[f], (str, int, float)) and not isinstance(rec[f], bool)]
                values[f] = list(dict.fromkeys(seen))
            schema[rt] = {"fields": fields, "values": values, "records": recs,
                          "ids": [rec["id"] for rec in recs if "id" in rec]}
    return schema


async def probe_authz(spec) -> list:
    """Run the authz/RBAC-bypass detectors. Returns list[Finding]."""
    findings: list = []
    # No-op on a target that doesn't expose this probe's tool contract, rather than
    # blowing up trying to call a tool that isn't there (a server may be pure exec /
    # fetch with no resource-query surface at all).
    try:
        async with open_session(spec, spec.most_permissive().name) as p:
            names = {t["name"] for t in await p.list_tools()}
    except Exception:
        return findings
    if T_LIST not in names:
        return findings
    try:
        schema = await _learn_schema(spec)
    except ToolError:
        return findings

    perm_name = spec.most_permissive().name
    all_resources = set(schema)
    for ident in spec.identities:
        if ident.name == perm_name:
            continue
        async with open_session(spec, ident.name) as s:
            try:
                accessible = {r.get("resource_type") for r in (await s.call(T_LIST)).get("resources", [])}
            except ToolError:
                continue
            for rt in sorted(accessible & all_resources):
                base = await s.call(T_QUERY, {"resource_type": rt, "limit": SAMPLE_LIMIT})
                base_recs = base.get("records", [])
                base_count = base.get("count", len(base_recs))
                base_ids = {rec["id"] for rec in base_recs if "id" in rec}
                if base_count <= 0:
                    continue
                role_fields: set = set()
                for rec in base_recs:
                    role_fields |= set(rec.keys())

                findings += await _filter_leak(s, rt, schema, role_fields, base_count, ident.name)
                findings += await _row_scope(s, rt, schema, base_recs, base_ids, ident.name)
                findings += await _id_enum(s, rt, schema, base_ids, ident.name)

            # IDOR into resources this role cannot access at all
            findings += await _forbidden_resource(s, schema, accessible, ident.name)
    return findings


async def _filter_leak(s, rt, schema, role_fields, base_count, identity) -> list:
    """Detector 1: redacted field usable as a filter predicate."""
    out = []
    for hf in sorted(schema[rt]["fields"] - role_fields):
        for value in schema[rt]["values"].get(hf, [])[:MAX_PROBE_VALUES]:
            probe = await s.call(T_QUERY, {"resource_type": rt, "filters": {hf: value}, "limit": SAMPLE_LIMIT})
            precs = probe.get("records", [])
            pcount = probe.get("count", len(precs))
            if 0 <= pcount < base_count:
                out.append(Finding(
                    probe_class="authz", severity="high",
                    title=f"Redacted field '{hf}' leaks through filter predicate on '{rt}'",
                    identity=identity,
                    repro={"tool": T_QUERY, "arguments": {"resource_type": rt, "filters": {hf: value}}},
                    evidence={
                        "redacted_field": hf, "probe_value": value,
                        "baseline_count": base_count, "filtered_count": pcount,
                        "leaked_records": [rec.get("name", rec.get("id")) for rec in precs],
                        "explanation": (f"'{hf}' is stripped from this role's output, but filtering on it "
                                        f"returns {pcount} of {base_count} rows. The role recovers the hidden "
                                        f"value of every record by which rows a filter matches."),
                    },
                    remediation=("Reject filters on fields redacted from the role -- enforce redaction at the "
                                 "query/dispatch layer, not only on the returned rows (see Warden 7188eed)."),
                ))
                break  # one value proves this field; move on
    return out


def _scoping_fields(rt, schema, base_recs) -> dict:
    """Fields where the role's baseline is a strict, low-cardinality subset of the
    permissive role's values -- i.e. the role looks row-scoped on that field."""
    out: dict = {}
    n_perm = len(schema[rt]["records"]) or 1
    for f, perm_vals in schema[rt]["values"].items():
        # skip near-unique keys (id, name): every value distinct -> not a scope axis
        if len(perm_vals) >= n_perm:
            continue
        role_vals = list(dict.fromkeys(
            rec[f] for rec in base_recs
            if f in rec and isinstance(rec[f], (str, int, float)) and not isinstance(rec[f], bool)))
        rv, pv = set(role_vals), set(perm_vals)
        if rv and rv < pv:                      # strict subset => scoped on f
            out[f] = sorted(pv - rv)
    return out


async def _row_scope(s, rt, schema, base_recs, base_ids, identity) -> list:
    """Detector 2: reach rows outside the role's scope via an out-of-scope filter value."""
    out = []
    for f, oos_vals in _scoping_fields(rt, schema, base_recs).items():
        for v in oos_vals[:MAX_PROBE_VALUES]:
            probe = await s.call(T_QUERY, {"resource_type": rt, "filters": {f: v}, "limit": SAMPLE_LIMIT})
            leaked = [rec for rec in probe.get("records", []) if rec.get("id") not in base_ids]
            if leaked:
                out.append(Finding(
                    probe_class="authz", severity="high",
                    title=f"Row-scope escalation on '{rt}': out-of-scope '{f}={v}' rows reachable by filter",
                    identity=identity,
                    repro={"tool": T_QUERY, "arguments": {"resource_type": rt, "filters": {f: v}}},
                    evidence={
                        "scope_field": f, "out_of_scope_value": v,
                        "escaped_records": [rec.get("name", rec.get("id")) for rec in leaked],
                        "explanation": (f"This role's unfiltered view is scoped on '{f}', but filtering "
                                        f"'{f}={v}' returns {len(leaked)} row(s) outside that scope. The filter "
                                        f"runs against the full dataset instead of the scoped one."),
                    },
                    remediation=("Apply row scoping BEFORE filters (and to every read path), so an explicit "
                                 "filter cannot reach rows the unfiltered query would not return."),
                ))
                return out  # one escape proves it for this resource
    return out


async def _id_enum(s, rt, schema, base_ids, identity) -> list:
    """Detector 3: retrieve out-of-scope ids in an accessible resource via get_record."""
    oos_ids = [i for i in schema[rt]["ids"] if i not in base_ids][:MAX_PROBE_IDS]
    leaked = []
    for rid in oos_ids:
        try:
            resp = await s.call(T_GET, {"resource_type": rt, "record_id": rid})
        except ToolError:
            continue
        if isinstance(resp, dict) and resp.get("record"):
            leaked.append(resp["record"].get("name", rid))
    if leaked:
        return [Finding(
            probe_class="authz", severity="high",
            title=f"ID enumeration on '{rt}': single-record lookup ignores row scope",
            identity=identity,
            repro={"tool": T_GET, "arguments": {"resource_type": rt, "record_id": oos_ids[0]}},
            evidence={
                "leaked_record_ids": oos_ids[:len(leaked)], "leaked": leaked,
                "explanation": (f"query_resource scopes this role's rows, but get_record returns records by id "
                                f"that are outside the role's scope ({len(leaked)} retrieved). The list path is "
                                f"governed and the detail path is not."),
            },
            remediation="Run get_record through the same scoping/redaction choke point as query_resource.",
        )]
    return []


async def _forbidden_resource(s, schema, accessible, identity) -> list:
    """Detector 3b: read a record from a resource the role cannot access at all."""
    out = []
    for rt in sorted(set(schema) - accessible):
        ids = schema[rt]["ids"][:1]
        if not ids:
            continue
        try:
            resp = await s.call(T_GET, {"resource_type": rt, "record_id": ids[0]})
        except ToolError:
            continue
        if isinstance(resp, dict) and resp.get("record"):
            out.append(Finding(
                probe_class="authz", severity="critical",
                title=f"Forbidden-resource access: '{rt}' readable via get_record despite no list access",
                identity=identity,
                repro={"tool": T_GET, "arguments": {"resource_type": rt, "record_id": ids[0]}},
                evidence={
                    "forbidden_resource": rt, "leaked_record": resp["record"].get("name", ids[0]),
                    "explanation": (f"This role cannot list '{rt}', but get_record returns one of its records. "
                                    f"Access control is enforced on list_resources/query_resource but not on "
                                    f"the by-id lookup."),
                },
                remediation="Enforce resource-level access on get_record, not only on list/query.",
            ))
    return out

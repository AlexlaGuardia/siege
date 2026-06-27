"""Positive tests: the authz detectors must FIRE on the intentionally-vulnerable
leaky fixture. Guards against the probes silently degrading into no-ops -- a
security scanner that never finds anything is worse than none.

    python -m tests.test_leaky
"""

import asyncio

from siege.probes.authz import probe_authz
from fixtures.leaky import spec


async def _run():
    findings = await probe_authz(spec())
    titles = [f.title for f in findings]

    assert any("Row-scope escalation" in t for t in titles), titles
    assert any("ID enumeration" in t for t in titles), titles
    assert any("Forbidden-resource" in t for t in titles), titles
    # no field is redacted on the leaky server, so the redaction-leak detector
    # must stay silent here (keeps fixtures' findings distinct)
    assert not any("Redacted field" in t for t in titles), titles
    # the forbidden-resource read is the worst case -> critical
    assert any(f.severity == "critical" for f in findings), [f.severity for f in findings]

    print(f"PASS  authz detectors fire on leaky: {len(findings)} findings")
    for f in findings:
        print(f"        [{f.severity}] {f.identity}: {f.title}")


if __name__ == "__main__":
    asyncio.run(_run())

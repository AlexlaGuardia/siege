"""Class D sink probe: catch-on-vuln + clean-on-fixed regression.

The exec_server fixture reproduces three confirmed codebug-hunt findings (allowlist
LOLBIN bypass, filename command-injection, path traversal). The probe must go LOUD
on the default build and SILENT on SIEGE_EXEC_FIXED=1 -- that pair is the whole test:
a probe that only fires is a smoke alarm taped to the on switch.

    python -m tests.test_sink
"""

import asyncio
import os

from siege.probes.sink import plant_canary, probe_sink, probe_sink_ssrf
from fixtures.exec import spec


async def _run():
    canary_path, canary_body = plant_canary()
    try:
        # --- vulnerable build: every detector fires ---
        vuln = await probe_sink(spec(), canary_path=canary_path, canary_body=canary_body)
        titles = [f.title for f in vuln]
        classes = {f.evidence.get("sink_param"): f.title for f in vuln}
        assert any("allowlist bypass" in t.lower() for t in titles), titles
        assert any("command injection" in t.lower() for t in titles), titles
        assert any("traversal" in t.lower() or "escape" in t.lower() for t in titles), titles
        # every finding carries a replayable repro and the canary that proved it
        for f in vuln:
            assert f.repro.get("tool") and f.repro.get("arguments"), f.title
            assert f.probe_class == "sink" and f.severity in ("critical", "high"), f.title

        # --- patched build: nothing fires (no false positives) ---
        fixed = await probe_sink(spec(fixed=True), canary_path=canary_path, canary_body=canary_body)
        assert fixed == [], [f.title for f in fixed]

        # --- SSRF sub-detector: loopback listener. Skips cleanly if it can't bind. ---
        ssrf_note = "skipped (no loopback)"
        vuln_ssrf, ran, reason = await probe_sink_ssrf(spec())
        if ran:
            assert any("ssrf" in f.title.lower() for f in vuln_ssrf), [f.title for f in vuln_ssrf]
            fixed_ssrf, _, _ = await probe_sink_ssrf(spec(fixed=True))
            assert fixed_ssrf == [], [f.title for f in fixed_ssrf]
            ssrf_note = f"{len(vuln_ssrf)} on vuln, 0 on fixed"

        print(f"PASS  sink probe: {len(vuln)} findings on vuln build "
              f"({len(set(classes))} sink params), 0 on fixed build; ssrf {ssrf_note}")
    finally:
        try:
            os.unlink(canary_path)
        except OSError:
            pass


if __name__ == "__main__":
    asyncio.run(_run())

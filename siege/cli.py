"""siege -- command line entry.

    python -m siege.cli scan --target warden [--json] [--report out.md]

--target names a built-in fixture (currently: warden). Custom targets land with
the HTTP transport in v0.2. Exit code is non-zero when findings exist, so Siege
drops cleanly into CI as a gate.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys

from siege.probes.authz import probe_authz
from siege.report import ScanResult

FIXTURES = {"warden": "fixtures.warden", "leaky": "fixtures.leaky"}


async def _scan(target: str, inject: bool, model: str | None) -> ScanResult:
    if target not in FIXTURES:
        raise SystemExit(f"unknown target {target!r}; built-in targets: {', '.join(FIXTURES)}")
    spec = importlib.import_module(FIXTURES[target]).spec()

    findings = await probe_authz(spec)
    coverage = ["authz"]
    not_tested = ["contract (Class C)"]

    if inject:
        from siege.agent import make_anthropic_complete
        from siege.probes.inject import probe_injection
        try:
            complete = make_anthropic_complete(model) if model else make_anthropic_complete()
            findings += await probe_injection(complete)
            coverage.append("inject")
        except RuntimeError as e:
            not_tested.append(f"inject (Class B): skipped -- {e}")
    else:
        not_tested.insert(0, "inject (Class B): pass --inject (uses the model API)")

    result = ScanResult(target=spec.name, findings=findings,
                        coverage=coverage, not_tested=not_tested)
    for f in findings:
        f.target = spec.name
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(prog="siege", description="Red-team a live MCP server.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="run probes against a target")
    scan.add_argument("--target", required=True, help=f"built-in fixture: {', '.join(FIXTURES)}")
    scan.add_argument("--inject", action="store_true",
                      help="also run Class B behavioral injection (uses the model API)")
    scan.add_argument("--model", help="model id for the injection agent (default: Haiku)")
    scan.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    scan.add_argument("--report", metavar="PATH", help="also write the report to PATH")
    args = parser.parse_args(argv)

    result = asyncio.run(_scan(args.target, args.inject, args.model))
    out = result.to_json() if args.json else result.to_markdown()
    print(out)
    if args.report:
        with open(args.report, "w") as f:
            f.write(out)
    # Gate on real findings; an info-level summary (e.g. "0/N hijacked") is not a failure.
    return 1 if any(f.severity != "info" for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())

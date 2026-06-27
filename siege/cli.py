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


async def _scan(target: str) -> ScanResult:
    if target not in FIXTURES:
        raise SystemExit(f"unknown target {target!r}; built-in targets: {', '.join(FIXTURES)}")
    spec = importlib.import_module(FIXTURES[target]).spec()

    findings = await probe_authz(spec)
    result = ScanResult(
        target=spec.name,
        findings=findings,
        coverage=["authz"],
        not_tested=["inject (Class B)", "contract (Class C)"],
    )
    for f in findings:
        f.target = spec.name
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(prog="siege", description="Red-team a live MCP server.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="run probes against a target")
    scan.add_argument("--target", required=True, help=f"built-in fixture: {', '.join(FIXTURES)}")
    scan.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    scan.add_argument("--report", metavar="PATH", help="also write the report to PATH")
    args = parser.parse_args(argv)

    result = asyncio.run(_scan(args.target))
    out = result.to_json() if args.json else result.to_markdown()
    print(out)
    if args.report:
        with open(args.report, "w") as f:
            f.write(out)
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())

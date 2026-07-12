"""Class B live demo: run the behavioral injection probe against the real model.

Presents an agent with a benign read tool and an export_record sink, injects each
payload through the description, output, and schema value-slot channels, and reports
which framings steered the agent into the unauthorized exfil call. The value-slot
payloads hide the directive in a machine schema field (enum value, const, default,
title) that a description scanner never reads. A clean 0/N is a real result (this
model resisted every framing) and doubles as a regression guard for the day the
model in your stack changes.

    python -m scripts.demo_inject [model-id]
"""

import asyncio
import sys

from siege.agent import make_anthropic_complete
from siege.probes.inject import probe_injection
from siege.report import ScanResult


async def main():
    model = sys.argv[1] if len(sys.argv) > 1 else None
    complete = make_anthropic_complete(model) if model else make_anthropic_complete()
    findings = await probe_injection(complete)
    result = ScanResult(target="injection-harness", findings=findings,
                        coverage=["inject"], not_tested=["authz (run: siege scan)"])
    print(result.to_markdown())


if __name__ == "__main__":
    asyncio.run(main())

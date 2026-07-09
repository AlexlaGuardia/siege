"""Generate the canned before/after snapshot the web demo serves.

Runs the SAME authz probe as scripts.demo_before_after — vulnerable Warden
(4938bdf) in a throwaway git worktree with a copied warden.db, then fixed Warden
(7188eed / live HEAD) — and writes siege/data/demo_run.json. web.py loads that
file and renders it; the scan never runs at serve time.

Re-run whenever the probe or Warden changes, then `pm2 restart siege-web`.

    cd /root/siege && python -m scripts.snapshot_demo
"""

import asyncio
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from scripts.demo_before_after import (
    _build_vulnerable_worktree,
    _cleanup_worktree,
    _scan,
    LIVE_WARDEN,
    VULN_COMMIT,
    FIXED_COMMIT,
)

OUT = Path(__file__).resolve().parent.parent / "siege" / "data" / "demo_run.json"


async def main() -> None:
    scratch = tempfile.mkdtemp(prefix="siege-warden-vuln-")
    vuln_dir = os.path.join(scratch, "warden")
    try:
        print(f"[*] Building vulnerable Warden ({VULN_COMMIT}) in isolated worktree...")
        _build_vulnerable_worktree(vuln_dir)
        before = await _scan(vuln_dir, f"vulnerable {VULN_COMMIT}")
        after = await _scan(LIVE_WARDEN, f"fixed {FIXED_COMMIT}")

        assert len(before.findings) >= 1, "vulnerable scan produced no findings — snapshot is wrong"
        assert len(after.findings) == 0, "fixed scan produced findings — snapshot is wrong"

        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "vuln_commit": VULN_COMMIT,
                    "fixed_commit": FIXED_COMMIT,
                    "before": json.loads(before.to_json()),
                    "after": json.loads(after.to_json()),
                },
                indent=2,
            )
        )
        print(f"[+] wrote {OUT}  ({len(before.findings)} before / {len(after.findings)} after)")
    finally:
        _cleanup_worktree(vuln_dir)  # load-bearing — leaves a dangling git worktree otherwise
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())

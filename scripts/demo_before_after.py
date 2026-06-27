"""Siege before/after demo against Warden.

Stands up the VULNERABLE Warden (commit 4938bdf) in a throwaway git worktree --
the live /root/warden checkout is never touched -- runs Siege's authz probe
against it, then runs the same probe against the FIXED Warden (current HEAD,
7188eed). Expected: HIGH finding on the vulnerable build, clean on the fixed one.

    python -m scripts.demo_before_after

This is the money shot: Siege auto-reproduces the real access-control bug that a
static manifest scanner cannot see, and confirms the fix closes it.
"""

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile

from siege.probes.authz import probe_authz
from siege.report import ScanResult

LIVE_WARDEN = "/root/warden"
VULN_COMMIT = "4938bdf"
FIXED_COMMIT = "7188eed"


def _git(*args, cwd=LIVE_WARDEN) -> str:
    return subprocess.run(["git", "-C", cwd, *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _build_vulnerable_worktree(dest: str):
    """Check out the vulnerable commit into an isolated worktree and seed its db."""
    _git("worktree", "add", "--detach", dest, VULN_COMMIT)
    # warden.db is gitignored; copy the seeded db from the live checkout so the
    # vulnerable server has data to leak.
    shutil.copy(os.path.join(LIVE_WARDEN, "warden.db"), os.path.join(dest, "warden.db"))


def _cleanup_worktree(dest: str):
    subprocess.run(["git", "-C", LIVE_WARDEN, "worktree", "remove", "--force", dest],
                   capture_output=True, text=True)


async def _scan(warden_dir: str, label: str) -> ScanResult:
    os.environ["WARDEN_DIR"] = warden_dir
    # import the fixture fresh so it picks up WARDEN_DIR
    import importlib
    import fixtures.warden as wf
    importlib.reload(wf)
    findings = await probe_authz(wf.spec())
    res = ScanResult(target=f"warden ({label})",
                     findings=findings,
                     coverage=["authz"],
                     not_tested=["inject (Class B)", "contract (Class C)"])
    for f in findings:
        f.target = res.target
    return res


async def main():
    scratch = tempfile.mkdtemp(prefix="siege-warden-vuln-")
    vuln_dir = os.path.join(scratch, "warden")
    try:
        print(f"[*] Building vulnerable Warden ({VULN_COMMIT}) in isolated worktree...")
        _build_vulnerable_worktree(vuln_dir)

        print(f"\n{'='*70}\nBEFORE — vulnerable Warden ({VULN_COMMIT})\n{'='*70}")
        before = await _scan(vuln_dir, f"vulnerable {VULN_COMMIT}")
        print(before.to_markdown())

        print(f"\n{'='*70}\nAFTER — fixed Warden ({FIXED_COMMIT}, live HEAD)\n{'='*70}")
        after = await _scan(LIVE_WARDEN, f"fixed {FIXED_COMMIT}")
        print(after.to_markdown())

        print(f"\n{'='*70}\nVERDICT\n{'='*70}")
        ok = len(before.findings) >= 1 and len(after.findings) == 0
        print(f"  vulnerable build: {len(before.findings)} finding(s)  (expect >=1)")
        print(f"  fixed build:      {len(after.findings)} finding(s)  (expect 0)")
        print(f"  {'PASS — Siege caught the bug and cleared the fix.' if ok else 'FAIL — unexpected result.'}")
        sys.exit(0 if ok else 1)
    finally:
        _cleanup_worktree(vuln_dir)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())

"""TargetSpec for the intentionally-vulnerable exec_server (Siege's positive test
target for the Class D sink probe). See fixtures/exec_server.py for the planted bugs.

spec()            -> the vulnerable default build (the interesting target).
spec(fixed=True)  -> the patched build; the sink probe must find NOTHING on it.
"""

import os
import sys

from siege.roles import Identity, TargetSpec

SIEGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def spec(fixed: bool = False) -> TargetSpec:
    env = {"SIEGE_EXEC_FIXED": "1"} if fixed else {}
    return TargetSpec(
        name="exec-fixed" if fixed else "exec",
        transport="stdio",
        command=[sys.executable, "-m", "fixtures.exec_server"],
        cwd=SIEGE_DIR,
        identities=[Identity("user", env=env, permissive=True)],
    )

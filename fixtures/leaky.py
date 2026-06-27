"""TargetSpec for the intentionally-vulnerable leaky_server (Siege's positive
test target). See fixtures/leaky_server.py for the planted bugs."""

import os
import sys

from siege.roles import Identity, TargetSpec

SIEGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def spec() -> TargetSpec:
    return TargetSpec(
        name="leaky",
        transport="stdio",
        command=[sys.executable, "-m", "fixtures.leaky_server"],
        cwd=SIEGE_DIR,
        identities=[
            Identity("admin", env={"LEAKY_ROLE": "admin"}, permissive=True),
            Identity("west", env={"LEAKY_ROLE": "west"}),
            Identity("support", env={"LEAKY_ROLE": "support"}),
        ],
    )

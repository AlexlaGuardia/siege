# Siege

**A runtime red-team harness for live MCP servers.** Point it at a running
server, it attacks as real roles, and it hands back the findings a static scanner
can't see — because the bug isn't in the manifest, it's in how the server behaves
when you actually exercise it.

Siege is the offense leg of an agent-governance suite: **[Warden](https://warden.alexlaguardia.dev)
governs, [Crumb](https://crumb.alexlaguardia.dev) attributes, Siege proves it holds.**

## Why runtime, not static

The MCP security tools that exist today (MCP-Scan / Snyk Agent Scan, Cisco's
scanner) read the tool *manifest*: they grep tool descriptions for poisoned
instructions. That catches a real class of attack. It cannot catch the class that
only exists when the server runs.

Concrete example, found and fixed in Warden:

> A `support` role has the `tier` field redacted from its output. The manifest
> looks clean. But `tier` was still accepted as a query *filter*, so support could
> run `query_resource("accounts", {"tier": "Enterprise"})` and recover the hidden
> tier of every account by which rows came back. A manifest scan returns green.

Siege catches it by behaving like the `support` role against the live server.

```
$ python -m scripts.demo_before_after

BEFORE — vulnerable Warden (4938bdf)
## 1. [HIGH] Redacted field 'tier' leaks through filter predicate on 'accounts'
   Found as role: support
   Reproduce: query_resource({"resource_type":"accounts","filters":{"tier":"Enterprise"}})
   leaked_records: ['Acme Corp', 'Initech', 'Umbrella Co', 'Hooli', 'Stark Industries', 'Wayne Enterprises']

AFTER — fixed Warden (7188eed)
   No findings. The probed classes held.

VERDICT: PASS — Siege caught the bug and cleared the fix.
```

## Probe classes

- **Class A — Authz / RBAC bypass** *(implemented)*. Exercises the server as each
  role and diffs what comes back: redacted-field filter leaks, row-scope
  escalation, id enumeration (IDOR), and forbidden-resource reads; error-channel
  leaks are next. The fresh part — nobody ships runtime authz probing for MCP.
- **Class B — Tool poisoning / injection** *(implemented)*. The *behavioral*
  version: present an agent with a benign read tool and an `export_record` sink,
  inject each payload through the description and output channels, and observe
  whether the agent fires the sink at an attacker destination it was never asked
  to. Reports which framings steered the model — a matrix, not a manifest grep.
  A clean `0/N` is a real result and a regression guard for model upgrades.
- **Class C — Silent failure / contract violation** *(planned)*. Does the server
  claim success while returning empty or wrong data?

Each report names the classes it ran and logs what it did not test. No
"finds all vulnerabilities."

## Usage

```bash
pip install -r requirements.txt
python -m siege.cli scan --target warden            # scan the built-in fixture
python -m siege.cli scan --target warden --json --report siege.json
python -m scripts.demo_before_after                 # the before/after proof
python -m tests.test_authz                          # fast self-check
```

`--target` names a built-in fixture (currently `warden`). Custom targets and the
HTTP transport land in v0.2 (stdio today).

## How it works

`siege/target.py` is a thin async adapter over the official `mcp` SDK: it opens a
session to the target *as a given identity* (an env override for stdio, a header
set for HTTP), lists tools, and calls them. `siege/probes/authz.py` learns the
schema and real values from the most-permissive identity, then for each restricted
identity diffs the visible fields and probes the hidden ones. Findings carry an
exact, replayable reproduction.

## Stack

Python and the official `mcp` SDK (client side). The authz class (Class A) is
pure deterministic diffing, no model. The behavioral injection class (Class B,
opt-in via `--inject`) drives an agent with Claude (Haiku by default,
`SIEGE_AGENT_MODEL` to override) and detects a hijack deterministically, by
observing whether the exfiltration tool actually fired at the attacker's
destination — not with an LLM judge. Findings are rendered to JSON or Markdown;
there is no database.

---

Built by [Alex LaGuardia](https://alexlaguardia.dev). MCP-only for v0.1; runtime,
behavioral, role-aware by design.

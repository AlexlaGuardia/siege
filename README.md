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
  inject each payload through the description, output, **and schema value-slot**
  channels, and observe whether the agent fires the sink at an attacker
  destination it was never asked to. Reports which framings steered the model — a
  matrix, not a manifest grep. A clean `0/N` is a real result and a regression
  guard for model upgrades.
  - The **value-slot channel** is the one a description scanner can't see: the
    same directive hidden in a machine schema slot (an `enum` value, `const`,
    `default`, `examples`, a property `title`, `additionalProperties`) instead of
    the human-readable description. Snyk agent-scan and Invariant mcp-scan walk the
    description and miss it; the model reads it as an instruction all the same. The
    marquee case is a tool whose description **explicitly denies exporting** yet
    still hijacks via the enum value — you cannot review or description-scan your
    way out. (Ported from the tool-definition surface map behind
    [Vigil](https://github.com/AlexlaGuardia/Vigil)'s `scan-tools` value-slot rule.)
- **Class D — Server-side execution sinks** *(implemented)*. Exercises the server's
  own code, not the agent: does a tool parameter reach a shell, a filesystem path,
  or (next) an outbound fetch? Targeting is schema-driven — Siege classifies each
  tool's string params into exec / path / url sinks and aims the matching canary at
  each — the runtime analog of a static taint scan, but *proven by execution*. A
  blind arithmetic oracle (`$((a*b))` resolves only when a shell evaluates it)
  separates real command execution from a tool that merely parrots your input back
  in an error, so a reflected payload is not a false positive. Detectors:
  - **allowlist bypass** — a tool that *claims* a safe/restricted command set still
    runs a non-allowlisted binary via a LOLBIN (`env`, `sh -c`). A shell tool with
    *no* safety claim is by-design and stays silent — the finding is a defeated
    control, not the mere ability to run a command.
  - **parameter injection** — a shell metacharacter in a *non-command* param (a
    filename, a tag) breaks into the shell the tool runs.
  - **path traversal / sandbox escape** — a path param reaches a Siege-planted
    canary file outside the intended root (absolute or `../`).
  - **SSRF** — a url param fetches a Siege-controlled *loopback* listener with no
    host validation. A safe fetcher blocks loopback/link-local/private ranges; one
    that reaches `127.0.0.1` reaches `169.254.169.254` by the same missing guard.
    Flags only a fetch Siege *observed* land, so a by-design public fetcher stays
    silent; degrades to `not_tested` where the listener can't bind.

  Every detector maps to a real, confirmed CVE-class finding — these are the
  receipts behind the class, not hypotheticals. Target repos are withheld while their
  advisories are in coordinated disclosure; the classes are exact:

  | Detector | Backed by |
  |---|---|
  | allowlist bypass | An MCP SSH server whose allowlist checks only the first token and ships `env`/`git` as exec primitives → RCE (critical, CWE-77/78). Plus two other command-runner servers (prefix-only check; LOLBIN). |
  | parameter injection | A media-processing MCP server: client `output_filename` interpolated unquoted into the shell command → CWE-78. |
  | path traversal | A code-execution MCP server: unsanitized `project_dir` bind-mounted into the "sandbox"; the sanitize guard compiled out of the default build → CWE-22. |
  | SSRF | A fetch/retrieval MCP server: a read tool fetches a client URL with zero host validation and follows redirects → `169.254.169.254` → CWE-918. |

  Static manifest scanners return green on every one — the schema says `string`; it
  can't say *unquoted into `sh -c`*. (Sink taxonomy shared with the static
  codebug-hunt scout that found them — the two are the same taint model, one at
  rest and one at runtime.)

  **Live-confirmed.** Pointed at a running third-party media-processing MCP server
  over real MCP stdio, the *generic* probe (no target-specific tuning) reports the
  injection as CRITICAL, proven by the out-of-band oracle — an injected command wrote
  a Siege canary to a file. The fixtures prove the probe; a live third-party server
  proves the pitch.
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

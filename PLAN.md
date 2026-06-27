# Siege — Build Plan

> Runtime red-team harness for live MCP servers. Point it at a running server, it
> attacks, it hands back a findings report. The offense leg of the agent-governance
> suite: **Warden governs, Crumb attributes, Siege proves it holds.**
>
> Status: SCOPED 2026-06-27. Target: 1-week MVP. Owner: Serberus (cc).

---

## 1. Positioning (honest, post-research)

The MCP security market in mid-2026 is owned by **static manifest scanners**:
- **MCP-Scan** (Invariant Labs → acquired by Snyk, now "Snyk Agent Scan"), ~2000+ GitHub stars. Reads tool descriptions; keyword + semantic + LLM analysis for tool poisoning, prompt injection, cross-origin escalation, rug-pull.
- **Cisco AI Defense mcp-scanner** — same shape, GitHub.
- **OWASP MCP Top 10 (2026)** — the taxonomy (tool poisoning, rug-pull, tool-shadowing, confused deputy, insufficient authorization, etc.).

What NOBODY ships: a tool that **actually exercises a running server as different roles and tries to break access control at runtime.** Cerbos / OWASP / the RBAC vendors all say "you should red-team authorization scope escalation" and "try the server with users in different roles" — as *manual advice*, not a product.

**Siege's wedge = the thing static scanners structurally cannot find.** The Warden redaction-filter bug is the proof: the tool manifest is clean, the leak only exists in runtime behavior of the `support` role. A manifest scan returns green; Siege catches it by *behaving like an attacker against the live server*.

Do NOT try to out-compete MCP-Scan on static tool-poisoning. Differentiate on **runtime + behavioral + role-aware**.

One-liner: **"Siege red-teams your live MCP server the way an attacker would — as real roles, against the running thing, not by reading the manifest."**

---

## 2. The three probe classes (MVP)

### Class A — Authz / RBAC bypass (THE WEDGE, lead here)
Exercise the server as each role and try to read what the role shouldn't see.
- **Filter-predicate leak** (the Warden bug): a field redacted from output but usable as a query filter → infer the hidden value from which rows return. Generalize: for every field a role *can't* see, try filtering/sorting/searching on it and detect signal leakage via differential row counts.
- **Region/row-scope escalation**: try to reach out-of-scope rows via filters, id enumeration (`get_record` on guessed ids), alternate tools.
- **Confused deputy / scope mismatch**: same query via two roles, diff the results; flag where a lower role gets data only a higher role should.
- **Error-channel leak**: does a denial error message reveal the value/existence it's denying?
- **Detection**: differential analysis (same probe across roles, compare), plus a deterministic oracle where we control the fixture. No LLM needed for most of this — it's behavioral diffing. THIS IS THE FRESH PART.

### Class B — Tool-poisoning / injection (table-stakes, but behavioral)
Static scanners grep the manifest. Siege does the **behavioral** version: inject a poisoned tool description OR poisoned tool output, run a real agent loop, and **judge (LLM) whether the agent actually got hijacked** (e.g. made the unauthorized `export_record` call to an attacker destination).
- Seed payloads from `/root/guardia-core/research/mcp-host-lab/` (`poisoned_tools.py`, `poisoned_outputs.py`) + JEF corpus.
- Differentiator vs MCP-Scan: "did the manifest look suspicious" (them) vs "did the agent get owned" (us).

### Class C — Silent failure / contract violation (nobody else does this)
Does the server claim success while returning empty/wrong/partial data? (Vigil/MCPWatch's thesis.) Probe: call tools with known-good inputs, assert response shape/contract, flag `isError`-swallowing and empty-but-OK responses.
- Lower priority than A/B for week 1 but it's a unique third leg — keep it in if time allows, otherwise v1.1.

---

## 3. Architecture

```
siege/
  cli.py            `siege scan <target>` entrypoint; flags for classes, roles, report path
  target.py         MCP target adapter over the official `mcp` SDK ClientSession
                    (stdio + streamable HTTP); connect, list_tools, call_tool, auth headers
  roles.py          Role/identity config for a target (env var, header, or token per role)
  probes/
    authz.py        Class A — role-differential + filter-leak + id-enum + error-channel
    inject.py       Class B — description/output poisoning injector + agent loop + judge
    contract.py     Class C — silent-failure / contract assertions
  judge.py          LLM-as-judge for Class B (reuse Warden's judge pattern: stronger model)
  report.py         Findings model (severity/repro/evidence) → JSON + rendered Markdown/HTML
  fixtures/         Built-in demo targets (Warden launcher, before/after)
  results.db        Run/finding persistence (SQLite)
```

**Findings schema:** `{id, class, severity, title, role, repro (exact tool+args), evidence (the leaked data / hijacked call), remediation}`.

---

## 4. Reuse map (from asset inventory — keeps it a week)

| Need | Reuse | Path / note |
|---|---|---|
| MCP client (stdio+HTTP) | **official `mcp` SDK v1.26.0, installed** | `ClientSession`, `stdio_client`, `streamable_http_client`. Zero to build. |
| Demo target | **Warden MCP server** | `/root/warden/server/mcp_server.py`, role via `WARDEN_ROLE` env |
| Before/after demo | **Warden commits** | vulnerable `4938bdf` → fixed `7188eed` (the redaction-filter fix) |
| Injection payloads | **your mcp-host-lab research** | `/root/guardia-core/research/mcp-host-lab/poisoned_tools.py` + `poisoned_outputs.py` (battle-tested: some models hijacked, some resisted) |
| Injection corpus | **JEF prompt corpus** | `/root/guardia-core/research/jef-prompts-*.md` (5 technique files) + `jef-runs/` evidence |
| LLM judge pattern | **Warden eval judge** | `/root/warden/eval/judge.py` — stronger-model-judges, oracle-anchored |
| Forensic pairing (v2) | **Crumb gateway** | `/root/crumb/crumb/gateway.py` — sign a hijacked call into the ledger as `on_behalf_assertion=unauthorized` |

Not installed and NOT needed: garak / pyrit / promptfoo. Your own MCP-specific payloads are better than their generic corpora for this.

---

## 5. MVP scope — in / out (no silent caps)

**In (week 1):**
- `siege scan` CLI against a stdio or HTTP MCP target.
- Class A (authz) full + Class B (injection) behavioral with judge.
- JSON + Markdown report.
- Warden before/after as the built-in demo (catches the redaction leak on `4938bdf`, clean on `7188eed`).
- Hosted demo page `siege.alexlaguardia.dev` showing a canned run (optional, end of week).

**Out (named, not hidden):**
- MCP servers only — NOT OpenAI function-calling agents (cross-vendor is v2, mirrors Crumb's later expansion).
- Class C (silent-failure) — keep if time, else v1.1.
- Crumb ledger pairing — v2 "forensic artifact" workflow.
- Auto-remediation / PRs — report only.
- Scanning arbitrary third-party servers in the demo — fixtures + opt-in targets only (authorization/scope hygiene; we attack our own stuff publicly).

**Honesty rail:** report names the classes it covers and logs what it does NOT test. No "finds all vulns."

---

## 6. Week plan (day-by-day, adjustable)

- **Day 1** — `target.py` over the mcp SDK (connect stdio+HTTP, list/call tools), `roles.py`, and a smoke test driving Warden. Repo init, README skeleton.
- **Day 2** — Class A `authz.py`: role-differential engine + filter-leak detector. Reproduce the Warden bug automatically on `4938bdf`; confirm clean on `7188eed`. THIS is the proof-of-value milestone.
- **Day 3** — finish Class A (id-enum, error-channel, scope escalation) + `report.py` (JSON + Markdown findings).
- **Day 4** — Class B `inject.py`: description/output poisoning injector seeded from mcp-host-lab + `judge.py` agent-hijack verdict. Wire JEF payloads.
- **Day 5** — `cli.py` polish, `results.db`, end-to-end run + clean report on Warden. Tests.
- **Day 6** — Dev.to write-up + README ("I broke my own governed demo by hand, then built the scanner that catches the class"). Optional `siege.alexlaguardia.dev` hosted canned-run page.
- **Day 7** — buffer / Class C if ahead / build-in-public thread + push public repo.

Commit early/often (Server SOP). Signal cortex at each milestone.

---

## 7. Demo / reach money shot

Run Siege against **pre-fix Warden (`4938bdf`)** → it auto-flags the redaction-filter bypass (severity HIGH, with the exact `query_resource("accounts", {"tier":"enterprise"})` repro and the leaked enterprise account names). Run against **post-fix (`7188eed`)** → clean, `ignored_filters` guardrail visible.

The narrative (build-in-public + interview): *"I found a real access-control bug in my own governed-MCP demo by hand — a hidden field that leaked through a filter. A static manifest scanner can't see it. So I built the scanner that exercises the server as a real attacker and catches that whole class. Here it is catching mine."*

That single story: (a) ties Warden+Crumb+Siege into one visible suite, (b) shows rigor (found+fixed own bug), (c) lands the differentiation vs MCP-Scan, (d) is the warm-access hook for the agent-governance cohort (Cerbos/Okta/etc.).

---

## 8. Risks & honest caveats

- **Class B needs an agent + judge** = real LLM cost per run. Bound it (small case set, cheap agent model, Opus judge only on the verdict). Reuse Warden's judge so it's calibrated.
- **"Yet another scanner" perception** — mitigate by NEVER pitching against MCP-Scan on static poisoning; always lead with runtime authz, which they don't do.
- **Generalizing Class A beyond Warden** — the filter-leak detector must work on arbitrary servers, not just hardcode Warden's schema. Design it to introspect `describe_resource`-style metadata where present, and degrade gracefully (probe what it can enumerate) where not. Document the limitation.
- **Scope/authorization** — only attack our own fixtures + explicitly opted-in servers in anything public.

---

## 9. Name

**Siege** pairs thematically with **Warden** (Warden defends the gate; Siege tests it). Landscape check showed no blocking collision with a known MCP/security tool. PyPI name to verify at publish time; fall back to `siege-mcp` if `siege` is taken. Name is cheap — don't block the build on it.

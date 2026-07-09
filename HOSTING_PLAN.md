# Siege — Hosting Plan (siege.alexlaguardia.dev)

> Goal: put Siege's before/after demo on a live, clickable page — the third leg of the
> agent-governance suite — mirroring Crumb's simple FastAPI hosting pattern.
> Status: SCOPED 2026-07-08. Owner: Serberus (cc). This is a **finishing job**, not a build:
> the harness works, the money-shot demo runs green, the hosting pattern is a known clone.

---

## 1. Why now (strategic)

The trio is 2/3 real to a hiring manager. Warden (governs) and Crumb (attributes) are live,
clickable, and demoable. **Siege (proves it holds) has no hosted presence** — no
siege.alexlaguardia.dev, no pm2 process, stalled at "Day 6" for ~11 days. The suite only
sells as a suite when all three are clickable.

Three reasons this is the right move right now:
- **Siege's story is the sharpest of the three:** "I found a real access-control bug in my
  own governed MCP demo by hand — a hidden field that leaked through a filter. A static
  manifest scanner returns green. So I built the scanner that behaves like the attacker
  against the live server and catches that whole class. Here it is catching mine."
- **It rides today's momentum.** Siege's entire thesis is *runtime behavioral testing catches
  what static manifest scanners miss.* The Snyk Agent Scan finding we filed today (#8, the
  enum-value description bypass) is exactly a static-scanner blind spot — Siege's PLAN even
  names Snyk Agent Scan (ex-MCP-Scan) as the incumbent it beats. The red-team runs are already
  producing Siege's evidence; hosting makes that visible.
- **It's cheap.** The value engine is done; we're wrapping a working artifact in a web page.

**Honest caveat:** hosting doesn't create demand. Same reach bottleneck as Warden/Crumb.
The return is a complete, coherent suite for the job lever + warm-access narrative, not traffic.

---

## 2. What already works (verified 2026-07-08)

`cd /root/siege && python -m scripts.demo_before_after` runs **green**:

```
BEFORE — vulnerable Warden (4938bdf): 1 HIGH finding
  [HIGH] Redacted field 'tier' leaks through filter predicate on 'accounts'
  role: support
  repro: query_resource({"resource_type":"accounts","filters":{"tier":"Enterprise"}})
  baseline_count: 8  ->  filtered_count: 6
  leaked: Acme Corp, Initech, Umbrella Co, Hooli, Stark Industries, Wayne Enterprises
  remediation: reject filters on fields redacted from the role (see Warden 7188eed)
AFTER — fixed Warden (7188eed): No findings. The probed classes held.
VERDICT: PASS — Siege caught the bug and cleared the fix.
```

That findings report **is** the demoable artifact. Everything below is about rendering it on a page.

Already in place:
- Harness: `siege/` (cli, target, roles, probes/{authz,inject,contract}, report, agent, payloads).
- Demo logic: `scripts/demo_before_after.py` (isolated git worktree of vuln Warden; live Warden untouched).
- Report model: `siege/report.py` (ScanResult + Finding; Markdown renderer already exists).
- Tunnel: single Cloudflare tunnel `3f89fa78`, config `/root/.cloudflared/config.yml`.
- The exact hosting pattern to clone (Crumb, below).

---

## 3. The pattern to clone — Crumb, not Warden

| | Crumb (clone this) | Warden (don't) |
|---|---|---|
| Serve | single FastAPI app: `uvicorn crumb.web:app --port 8730` | Next.js app in `/root/warden/web` :3006 |
| Stack | Python (Siege is already Python) | Node/Next |
| Register | dark, **monospace, forensic** — status bands + a findings/ledger table | dark, **console** — nav tabs + live-run forms |
| Fit for Siege | ✅ Siege outputs a findings *report* → forensic register fits | ✗ heavier, wrong shape |

Siege serves a canned page from a small FastAPI app. No Next.js, no build step, no node.

---

## 4. Design / UX spec (from the live sibling study)

Lean the **Crumb register**: dark background, monospace body, `Siege.` title with the period
motif, colored status bands (green = clean / amber-red = finding), a findings card.

Page sections, top to bottom:

1. **Header** — `Siege.` + one-liner:
   *"Siege red-teams your live MCP server the way an attacker would — as real roles, against
   the running thing, not the manifest."* Top-right: `View source` → the Siege repo (like Warden).

2. **Suite banner** (NEW, see §6h) — `Warden governs · Crumb attributes · Siege proves it holds`,
   each linked. Makes the trio read as one system.

3. **The money-shot — a before/after toggle.** Two pre-computed states the visitor flips between
   (Crumb's interactive feel, but canned — no live compute per click):
   - **Scan vulnerable Warden (4938bdf)** → amber/red band: `1 HIGH FINDING` + the finding card.
   - **Scan fixed Warden (7188eed)** → green band: `CLEAN — the probed classes held.`

4. **Finding card** (the vulnerable state) — severity badge `HIGH`, title, role `support`, the
   exact repro in a mono code block, baseline→filtered counts, the leaked account names, the
   explanation, the remediation. This is the whole pitch in one card.

5. **Why runtime, not static** — one tight paragraph: *a static manifest scan returns green;
   the bug only exists in how the server behaves when you exercise it as the `support` role.*
   Tie-in line to the Snyk finding is optional but strong.

6. **Honesty rail** — render the report's own coverage line: *"Coverage: authz. Not tested this
   run: inject (Class B), contract (Class C)."* No "finds all vulns." Matches the PLAN's honesty rail.

7. **Footer** — repo link, suite links again.

Colors: green = clean/pass, amber-red = finding, mono throughout. Match Crumb's spacing/weight.

---

## 5. Build steps

| # | Step | What | Est |
|---|------|------|-----|
| 1 | **Snapshot the run** | `scripts/snapshot_demo.py`: run the same authz probe before/after (as `demo_before_after.py` does) and serialize both ScanResults to `siege/data/demo_run.json`. Canned, so the page never spins a worktree per request. | 20m |
| 2 | **`siege/web.py` + `static/index.html`** | FastAPI app cloned from `crumb/web.py`: load `demo_run.json`, **server-render** the two scans into a cloned `crumb/static/index.html` (Crumb uses one self-contained inline-CSS file, no Jinja). `report.py` has `to_json`/`to_markdown` but **no HTML renderer** — the HTML render lives in `web.py` (reads the plain dict from `to_json()`). Before/after = two server-rendered panels + a tiny toggle. | 1.5–2h |
| 3 | **Deps** | **Already satisfied** — `fastapi 0.128.8`, `uvicorn 0.40.0` import fine in the box's Python; `web.py` needs no Jinja. Just append them to `requirements.txt` for fresh-env hygiene. No `pip install` needed. | 5m |
| 4 | **PM2** | Add `siege-web` = `uvicorn siege.web:app --host 127.0.0.1 --port 8740` (cwd /root/siege); clone Crumb's ecosystem entry; `pm2 save`. | 15m |
| 5 | **Tunnel + DNS** | Add ingress block to `config.yml` (before the catch-all): `siege.alexlaguardia.dev → http://127.0.0.1:8740`. Then `cloudflared tunnel route dns 3f89fa78-d3c2-4b60-81fa-f804e7b77064 siege.alexlaguardia.dev` and restart cloudflared. | 15m |
| 6 | **Verify** | `curl -sI https://siege.alexlaguardia.dev` → 200; page renders; toggle works; suite links resolve. | 15m |
| 7 | **Suite banner retrofit** (optional, §6h) | Add the `govern · attribute · prove` banner to Warden + Crumb too, so all three cross-link. Warden = Next.js edit, Crumb = FastAPI template edit. | 45m |
| 8 | **Portfolio card** (optional) | Add Siege to alexlaguardia.dev so the trio shows together (Warden/Crumb/Siege). | 30m |

**Core (steps 1–6): ~half a day.** Steps 7–8 are the "make it a suite" polish, do-after.

Cloudflared ingress block to insert (exact, mirrors the crumb line at config.yml:67-69):
```yaml
  # Siege — runtime MCP red-team harness (FastAPI :8740)
  - hostname: siege.alexlaguardia.dev
    service: http://127.0.0.1:8740
```

---

## 6. Risks & decisions

- **Canned, not live** (decided). Running a real scan per pageview spins git worktrees of Warden
  — slow and heavy. Snapshot once, render static. A "live scan" mode is a v2 (needs a sandboxed
  target, rate limits, abuse handling). The before/after **toggle** gives the interactive feel
  without the cost.
- **Scope / authorization** (rail). The demo only ever attacks **our own** fixture (Warden). The
  page must not invite scanning arbitrary third-party servers. Matches PLAN §5.
- **Honesty rail** (rail). The page names what it tests and what it doesn't. No "finds all vulns."
- **Worktree hygiene.** `demo_before_after.py` creates a throwaway Warden worktree; the snapshot
  script must clean it up (`git worktree remove`) so we don't leave detached checkouts around.
- **Suite banner is scope creep if rushed.** It touches all three repos. Ship Siege's own page
  first (steps 1–6), then retrofit the banner as a deliberate follow-up (step 7).
- **Reach, not build, is the real bottleneck** (named up front). This completes the suite; it does
  not create demand. Distribution of the trio is a separate motion (warm-access cohort + articles).

---

## 7. Open questions for Alex

1. **Copy voice** — run the page's headline + "why runtime" paragraph through @pride, or keep it
   plain-technical like the current Crumb/Warden copy? (Rec: light pride pass on the one-liner +
   the why-runtime graf; the findings card stays raw/technical.)
2. **Class B teaser?** — authz (Class A) is the shipped, no-LLM money-shot. Do we *mention* the
   injection (Class B) capability on the page as "also covers behavioral tool-poisoning," or keep
   the page strictly to what the canned run proves (authz only)? (Rec: authz-only for the demo;
   one honest line that Class B exists but isn't in this canned run.)
3. **Suite banner now or later** — retrofit across all three this pass (step 7), or ship Siege
   solo first and batch the banner later? (Rec: ship Siege solo, banner as a fast follow.)
4. **Snyk tie-in on the page** — name the static-scanner blind spot explicitly (ties to today's
   filing), or keep it generic? (Rec: generic on the page; save the specific Snyk finding for the
   article/outreach so the page doesn't read as a callout.)

---

## 8. Build appendix (verified specifics)

Extracted from the Crumb/Siege code — everything below is confirmed on the box today.

**Architecture (the decision that drives it all):** Crumb's site is *live* (it mutates an on-disk
ledger per request). Siege's is **canned** — the expensive part (git worktree of Warden `4938bdf`
+ `warden.db` copy + async authz probe) runs **once, offline**, into `siege/data/demo_run.json`;
`web.py` just loads that JSON and renders HTML. No worktree, no async, no Warden dependency at
serve time.

**Confirmed facts:**
- `fastapi 0.128.8` / `uvicorn 0.40.0` / `jinja2 3.1.6` all import in the box Python. Crumb uses
  **no Jinja** — it serves one self-contained `crumb/static/index.html` (inline `<style>` +
  inline `<script>`) via explicit routes. Clone that file as Siege's styling base.
- Crumb's design tokens (`--bg:#0b0e14 --panel:#11151f --ink:#e6edf3 --accent:#7ee787 green
  --bad:#ff7b72 red --amber`, monospace body, `.banner.ok/.banner.bad`) already give the exact
  green-clean / red-finding visual. Map green→clean/fixed, red→HIGH/vulnerable.
- Port **8740 is free**. `crumb-web` has **no ecosystem file** — started via `pm2 start bash`.
- `report.py` = `to_json()` + `to_markdown()`, **no HTML renderer, no `from_json`**. Render in
  `web.py` off the plain dict; leave `report.py` untouched.
- Crumb's page is **fully public** (no owner-gate) and needs **no env vars**. Siege matches. Pure
  Python, no native/better-sqlite deps.
- `*.json` is not gitignored, so `demo_run.json` commits fine (leaked names are demo data, safe).

**Files to create:** `siege/web.py`, `siege/static/index.html` (clone crumb's), `scripts/snapshot_demo.py`,
`siege/data/demo_run.json` (generated). The full `web.py` skeleton + `snapshot_demo.py` (reusing
`demo_before_after.py`'s `_build_vulnerable_worktree`/`_scan`/`_cleanup_worktree`) are captured in
the session record — mirror crumb's route shape: `@app.get("/", HTMLResponse)` returns the rendered
`static/index.html`; `/api/demo` serves the JSON; `favicon.ico`→204; `icon.svg`/`og.png` routes.

**Deploy commands (exact):**
```bash
# 1. generate the canned snapshot (build-time, manual — never at serve time)
cd /root/siege && python -m scripts.snapshot_demo

# 2. pm2 (clone of crumb-web's bash-wrapped invocation)
pm2 start bash --name siege-web --cwd /root/siege -- -c \
  "python3 -m uvicorn siege.web:app --host 127.0.0.1 --port 8740"
pm2 save

# 3. DNS route (alexlaguardia.dev already routes through this tunnel)
cloudflared tunnel route dns 3f89fa78-d3c2-4b60-81fa-f804e7b77064 siege.alexlaguardia.dev
```
Then add the ingress block from §5 to `config.yml` **right after the crumb block, before the
catch-all** (`- service: http://127.0.0.1:3000` must stay last), and restart the tunnel
(`systemctl restart cloudflared` — **Kage owns this step**).

**Gotchas (load-bearing):**
1. `snapshot_demo.py` creates a detached git worktree in `/root/warden` — the `finally`
   cleanup (`git worktree remove` + `prune`) must run, or it leaves a dangling checkout. Only the
   snapshot script touches `/root/warden`; `web.py` never does.
2. `Finding.evidence` holds nested lists (`leaked_records`) + multi-line strings — JSON-encode
   non-str values and **HTML-escape everything** (we surface leaked names; escape, don't inject raw).
3. `warden.db` is gitignored + copied from the live checkout at snapshot time — if it's ever
   absent the before-scan is empty and the snapshot `assert` trips (fail loud, good).
4. **Stale snapshot:** the page is only as fresh as the last `snapshot_demo.py` run. Surface
   `generated_at` on the page so staleness is visible; re-run + `pm2 restart siege-web` after any
   probe/Warden change.
5. Copy/design for `static/index.html` should go through the `copywrite` + `web-design-guidelines`
   skills at build time (+ optional @pride pass on the one-liner per §7 Q1).

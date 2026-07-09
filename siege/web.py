"""Siege web — the before/after demo (canned).

One small FastAPI app, no build step. It serves a self-contained HTML page that
shows Siege's authz probe catching a real access-control bug on vulnerable Warden
(4938bdf) and clearing the fix (7188eed). The scan is pre-computed offline into
data/demo_run.json by scripts/snapshot_demo.py — this server never runs a probe,
a worktree, or Warden. Loads the JSON, renders HTML.

Run: uvicorn siege.web:app --host 127.0.0.1 --port 8740
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response

HERE = Path(__file__).parent
DEMO = HERE / "data" / "demo_run.json"

app = FastAPI(title="Siege", docs_url=None, redoc_url=None)


def _load() -> dict:
    return json.loads(DEMO.read_text())


def _fmt(v) -> str:
    """Evidence values are strings, ints, or lists — render readably, escaped."""
    if isinstance(v, list):
        return ", ".join(escape(str(x)) for x in v)
    return escape(str(v))


def _render_scan(scan: dict) -> str:
    """One ScanResult dict -> the banner + coverage + finding cards, HTML-escaped."""
    findings = scan.get("findings", [])
    target = escape(scan.get("target", ""))
    if not findings:
        head = (
            '<div class="banner ok"><span class="mark">CLEAN ✓</span>'
            f'<div><div>No findings. The probed classes held on <code>{target}</code>.</div>'
            '<div class="sub">Same probe, same roles. The fix rejects filters on redacted fields, '
            'so the leak closes.</div></div></div>'
        )
        return head
    sev = ", ".join(f"{n} {escape(k)}" for k, n in scan["summary"]["by_severity"].items())
    head = (
        '<div class="banner bad"><span class="mark">⚠ FINDING</span>'
        f'<div><div><b>{scan["summary"]["total"]} finding(s):</b> {escape(sev)} '
        f'on <code>{target}</code></div>'
        '<div class="sub">A static manifest scan returns green here. The bug only exists in how '
        'the server behaves when exercised as a real role.</div></div></div>'
    )
    cards = []
    for f in findings:
        args = json.dumps(f["repro"].get("arguments", {}))
        repro = f'{escape(f["repro"]["tool"])}({escape(args)})'
        rows = "".join(
            f'<div class="ev"><span class="k">{escape(str(k))}</span>'
            f'<span class="v">{_fmt(v)}</span></div>'
            for k, v in f.get("evidence", {}).items()
        )
        cards.append(
            f'<div class="finding sev-{escape(f["severity"])}">'
            f'<div class="ftitle"><span class="sevtag">{escape(f["severity"].upper())}</span>'
            f' {escape(f["title"])}</div>'
            f'<div class="meta">class <code>{escape(f["probe_class"])}</code>'
            f' · found as role <code>{escape(f["identity"])}</code></div>'
            f'<div class="repro"><span class="rlabel">reproduce</span> <code>{repro}</code></div>'
            f'<div class="evwrap">{rows}</div>'
            f'<div class="remediation"><span class="rlabel">fix</span> {escape(f["remediation"])}</div>'
            f'</div>'
        )
    return head + "".join(cards)


def _render_coverage(scan: dict) -> str:
    cov = ", ".join(escape(c) for c in scan.get("coverage", [])) or "none"
    out = f'Coverage this run: <b>{cov}</b>.'
    if scan.get("not_tested"):
        out += ' Not tested: ' + ", ".join(escape(n) for n in scan["not_tested"]) + "."
    return out


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    data = _load()
    tmpl = (HERE / "static" / "index.html").read_text()
    return (
        tmpl.replace("<!--BEFORE-->", _render_scan(data["before"]))
        .replace("<!--AFTER-->", _render_scan(data["after"]))
        .replace("<!--COVERAGE-->", _render_coverage(data["before"]))
        .replace("<!--VULN-->", escape(data.get("vuln_commit", "")))
        .replace("<!--FIXED-->", escape(data.get("fixed_commit", "")))
        .replace("<!--GENERATED-->", escape(data.get("generated_at", "")))
    )


@app.get("/api/demo")
def api_demo() -> JSONResponse:
    """The raw before/after scan JSON — machine-readable, public by design."""
    return JSONResponse(_load())


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)

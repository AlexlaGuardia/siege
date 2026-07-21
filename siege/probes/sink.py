"""Class D -- runtime server-side execution-sink safety (RCE / injection / traversal / SSRF).

The other Siege classes exercise *authorization* (who can reach what) and *the
agent* (does a poisoned manifest hijack the model). This class exercises the
SERVER'S OWN CODE: does a tool parameter reach a shell, a filesystem path, or an
outbound fetch in a way the manifest can't reveal? A static scanner reads the
tool schema and sees `output_filename: string`; it cannot see that the string is
interpolated, unquoted, into `sh -c`. Siege sends a canary through the parameter
and watches whether it fires. Observed, not inferred.

Targeting is schema-driven -- the runtime analog of the codebug-hunt static scout
(`research/codebug-hunt/sink_triage.py`): classify each tool's string params into
sink candidates (exec / path / url) by name+description, then aim the matching
canary at each. Server-agnostic: no hardcoded tool or field names.

Detectors, each mapped to a REAL confirmed finding (the receipts that back this
class). Target repos are anonymized while their advisories are in coordinated
disclosure; restore the names once each is public.

  1. allowlist-bypass  -- a tool that CLAIMS a restricted/safe/whitelisted command
     set still runs a non-allowlisted binary via a LOLBIN or a second token.
     Receipt: an MCP SSH server whose allowlist checks only the first token and ships
     env/docker/git as exec primitives -> RCE (critical, CWE-77/78; advisory pending).
     Also two other command-runner servers (prefix-only check; LOLBIN). We flag ONLY
     when a control is CLAIMED and defeated -- a shell tool with no safety claim is
     by-design, not a finding (a self-disclaimed filter is a watch, not a finding; a
     server that claims nothing is a clean negative).

  2. param-injection  -- a metacharacter in a NON-command parameter (a filename, a
     tag, an id) breaks out into the shell the tool runs.
     Receipt: a media-processing MCP server -- a client `output_filename` interpolated
     unquoted into the shell command -> command injection (CWE-78).

  3. path-traversal / sandbox-escape  -- a path parameter reaches a file outside the
     intended root (absolute path or `../`), so the "sandbox" reads/mounts host paths.
     Receipt: a code-execution MCP server -- unsanitized `project_dir` bind-mounted
     into the container; the sanitize guard compiled out of the default build (CWE-22).

  4. ssrf  -- a url parameter is fetched with no host validation, so the server
     reaches a Siege-controlled (and by extension an internal / metadata) endpoint.
     Receipt: a fetch/retrieval MCP server -- a read tool fetches a client URL with zero
     host validation and follows redirects -> 169.254.169.254 (CWE-918).

Detection is deterministic and benign: every canary is a unique token echoed/served
by Siege; a finding requires that exact token to come back through the tool's own
response (or Siege's loopback listener). Payloads never destroy or exfiltrate --
they prove the reachable primitive, nothing more.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import os
import secrets
import tempfile
import threading

from siege.report import Finding
from siege.target import ToolError, open_session


def plant_canary() -> tuple[str, str]:
    """Write a unique canary to a temp file OUTSIDE any target workspace and return
    (absolute_path, body). The path-traversal detector aims a path param at it; if
    the body comes back through a tool, the sandbox was escaped. Caller unlinks it."""
    body = "SIEGE-CANARY-" + secrets.token_hex(6)
    fd, path = tempfile.mkstemp(prefix="siege_canary_")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    return path, body

# --- schema-driven sink classification (the runtime taint hints) ------------------

_EXEC_NAME = ("command", "cmd", "exec", "execute", "shell", "script", "run", "bash",
              "sh", "program", "argv", "args", "code")
_EXEC_DESC = ("execute", "run a command", "run the", "shell", "terminal", "spawn",
              "invoke", "runs the", "arbitrary command")
# Words that mean "this tool drives an external process" even when no param is the
# raw command -- the B1 shape (a media/convert/download tool that shells out).
_INVOKES_PROC = ("execute", "run", "shell", "convert", "compile", "download", "fetch",
                 "render", "ffmpeg", "git ", "build", "spawn", "transcode", "process ")
_CLAIM = ("allowlist", "allow-list", "whitelist", "allowed command", "permitted",
          "restricted", "safe", "sandbox", "secure", "pre-approved", "approved",
          "only these", "cannot run", "blocked")
_PATH_NAME = ("path", "file", "filepath", "filename", "dir", "directory", "folder",
              "project_dir", "projectdir", "cwd", "workdir", "location", "src",
              "source", "dest", "destination", "output", "input", "target")
_URL_NAME = ("url", "uri", "endpoint", "host", "hostname", "link", "address",
             "webhook", "callback", "remote", "site", "resource_url", "feed")

MAX_TOOLS = 40   # bound the sweep on a large server


def _string_params(tool: dict) -> dict:
    """param_name -> param_description, for every string-typed input param."""
    schema = tool.get("input_schema") or {}
    props = schema.get("properties") or {}
    out = {}
    for name, spec in props.items():
        if not isinstance(spec, dict):
            continue
        t = spec.get("type")
        if t == "string" or (isinstance(t, list) and "string" in t) or t is None:
            out[name] = (spec.get("description") or "")
    return out


def _has(text: str, needles) -> bool:
    t = text.lower()
    return any(n in t for n in needles)


def _classify(tool: dict) -> dict:
    """Return {exec:[params], path:[params], url:[params], claims:bool, invokes:bool}."""
    name, desc = tool.get("name", ""), tool.get("description", "")
    params = _string_params(tool)
    exec_p, path_p, url_p = [], [], []
    for p, pdesc in params.items():
        blob = f"{p} {pdesc}"
        if _has(p, _EXEC_NAME) or _has(pdesc, _EXEC_DESC):
            exec_p.append(p)
        elif _has(p, _URL_NAME):
            url_p.append(p)
        elif _has(p, _PATH_NAME):
            path_p.append(p)
    claims = _has(f"{name} {desc}", _CLAIM) or any(_has(d, _CLAIM) for d in params.values())
    invokes = bool(exec_p) or _has(f"{name} {desc}", _INVOKES_PROC)
    return {"exec": exec_p, "path": path_p, "url": url_p,
            "claims": claims, "invokes": invokes, "params": params}


def _oracle() -> tuple[str, str]:
    """A blind-injection oracle. Returns (shell_expr, marker) where the marker
    appears ONLY if a shell actually evaluated the expression -- the arithmetic
    `$((a*b))` resolves to the product on execution, but a mere reflection of the
    payload back into a response (e.g. an error echoing a bad filename) shows the
    literal `$((a*b))`, not the product. That is what stops a tool that parrots its
    input from reading as a command-injection false positive."""
    a, b = secrets.randbelow(400) + 100, secrets.randbelow(400) + 100
    pre, post = "SIEGE", "Z" + secrets.token_hex(3).upper()
    expr = f"echo {pre}$(({a}*{b})){post}"      # sent
    marker = f"{pre}{a * b}{post}"              # only present if executed
    return expr, marker


def _blob(resp) -> str:
    """Flatten a tool response to a searchable string (canary lives somewhere in it)."""
    try:
        import json
        return json.dumps(resp, default=str)
    except Exception:
        return str(resp)


def _benign_value(name: str, spec: dict, real_file: str):
    """A harmless, schema-valid value for a non-sink param. Path-shaped params get a
    real planted file so a server that existence-checks its inputs (fs.access/stat)
    proceeds to the sink instead of bailing early -- the difference between reaching a
    real server's vulnerable line and stopping at its front-door validation."""
    t = spec.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), t[0] if t else "string")
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return False
    if t == "array":
        it = (spec.get("items") or {}).get("type")
        if it in ("integer", "number"):
            return [1]
        return [real_file] if _has(name, _PATH_NAME) else ["x"]
    if t == "object":
        return {}
    return real_file if _has(name, _PATH_NAME) else "x"


def _fill_args(tool: dict, sink_param: str, sink_value: str, real_file: str) -> dict:
    """Build a call satisfying the tool's required params, with sink_param carrying
    the payload. Only required params (plus the sink, which may be optional) are set,
    to avoid tripping optional-param validation we don't need."""
    schema = tool.get("input_schema") or {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    args = {}
    for name in required | {sink_param}:
        if name == sink_param:
            args[name] = sink_value
        else:
            args[name] = _benign_value(name, props.get(name, {}), real_file)
    return args


# --- detector 1: allowlist bypass -------------------------------------------------

# LOLBIN / second-token payloads: each is a benign canary echo reached THROUGH a
# primitive a naive allowlist tends to permit (env, sh -c, a shell operator).
def _lolbin_payloads():
    # Each proves a shell/exec PRIMITIVE spawned an arbitrary command of our choosing.
    # A bare `echo {marker}` is deliberately excluded -- echo may be legitimately
    # allowlisted, so its return is not proof of a bypass. env/sh spawning our
    # canary IS: that is the allowlist-ships-primitives shape (a first-token check is not a boundary).
    expr, marker = _oracle()
    return [
        ("env-lolbin", f"env {expr}", marker),
        ("sh-c", f"sh -c '{expr}'", marker),
    ]


async def _allowlist_bypass(s, tool, cls, identity, real_file) -> list:
    if not (cls["exec"] and cls["claims"]):
        return []
    out = []
    for ep in cls["exec"]:
        for label, payload, marker in _lolbin_payloads():
            args = _fill_args(tool, ep, payload, real_file)
            try:
                resp = await s.call(tool["name"], args)
            except ToolError:
                continue
            if marker in _blob(resp):
                out.append(Finding(
                    probe_class="sink", severity="critical",
                    title=f"Command-allowlist bypass on '{tool['name']}' via {label}",
                    identity=identity,
                    repro={"tool": tool["name"], "arguments": args},
                    evidence={
                        "sink_param": ep, "payload": payload, "canary": marker,
                        "explanation": (f"The tool claims a restricted command set, but the "
                                        f"'{label}' payload ran and echoed the Siege canary back. "
                                        f"A non-allowlisted binary executed -- the allowlist is not a "
                                        f"security boundary."),
                    },
                    remediation=("Validate the resolved program AND reject shell/exec primitives "
                                 "(env, sh, bash, -c, xargs, find -exec). An allowlist of command "
                                 "names is not a boundary when a member can spawn other binaries "
                                 "(the allowlist-ships-primitives class, CWE-77/78)."),
                ))
                break  # one payload proves this param
    return out


# --- detector 2: parameter injection ----------------------------------------------

def _inject_payloads():
    """Two detection channels. The arithmetic ones read the marker back out of the
    tool RESPONSE (works when the tool echoes command output). The out-of-band ones
    write a marker to a Siege-checked file, so a blind sink -- one that reflects
    nothing, or throws away stdout on error (the ffmpeg-mcp shape) -- is still caught.
    Each payload is (label, value, response_marker_or_None, oob_path_or_None, oob_marker)."""
    expr, marker = _oracle()
    oob_path = os.path.join(tempfile.gettempdir(), "siege_oob_" + secrets.token_hex(6))
    oob_marker = "SIEGEOOB" + secrets.token_hex(4).upper()
    # Out-of-band (side-channel) payloads FIRST: they detect a blind sink and don't
    # depend on the tool reflecting anything, so a hit is banked before any
    # response-reflection payload that a downstream command failure could disrupt.
    return [
        ("oob-write", f"x; echo {oob_marker} > {oob_path}", None, oob_path, oob_marker),
        ("oob-subshell", f"x$(echo {oob_marker} > {oob_path})", None, oob_path, oob_marker),
        ("semicolon", f"x; {expr}", marker, None, None),
        ("and", f"x && {expr}", marker, None, None),
        ("subshell", f"x$({expr})", marker, None, None),
    ]


def _oob_fired(oob_path, oob_marker) -> bool:
    try:
        with open(oob_path) as f:
            return oob_marker in f.read()
    except OSError:
        return False


async def _param_injection(s, tool, cls, identity, real_file) -> list:
    """A metachar in a NON-command param breaks into the shell the tool runs. We probe
    every non-exec string param, NOT just tools whose description advertises that it
    runs a process -- detection is execution-proven (an out-of-band file write or an
    evaluated arithmetic canary), so a tool that never shells out simply doesn't fire.
    A description-keyword gate here would only produce false NEGATIVES (a real case:
    ffmpeg-mcp's `concatenate_videos`, whose description names no exec verb yet shells
    out). We still exclude the exec param so a by-design command tool isn't flagged."""
    side_params = [p for p in (cls["path"] + cls["url"] + list(cls["params"]))
                   if p not in cls["exec"]]
    seen, out = set(), []
    for sp in side_params:
        if sp in seen:
            continue
        seen.add(sp)
        for label, payload, marker, oob_path, oob_marker in _inject_payloads():
            args = _fill_args(tool, sp, payload, real_file)
            try:
                resp = await s.call(tool["name"], args)
            except ToolError:
                resp = {}
            oob_hit = bool(oob_path) and _oob_fired(oob_path, oob_marker)
            resp_hit = bool(marker) and marker in _blob(resp)
            if oob_path:
                with contextlib.suppress(OSError):
                    os.unlink(oob_path)
            if oob_hit or resp_hit:
                proof = ("wrote a marker to a Siege-controlled file out-of-band"
                         if oob_hit else "echoed the Siege canary back in the response")
                out.append(Finding(
                    probe_class="sink", severity="critical",
                    title=f"Command injection on '{tool['name']}' via '{sp}' ({label})",
                    identity=identity,
                    repro={"tool": tool["name"], "arguments": args},
                    evidence={
                        "sink_param": sp, "payload": payload,
                        "canary": oob_marker if oob_hit else marker,
                        "channel": "out-of-band file write" if oob_hit else "response reflection",
                        "explanation": (f"The '{sp}' parameter is not a command, but a '{label}' "
                                        f"metacharacter in it caused an injected command that {proof}. "
                                        f"The value is interpolated into a shell without quoting."),
                    },
                    remediation=("Never build a shell string from a parameter. Pass arguments as an "
                                 "argv list to exec/spawn (no shell), or reject shell metacharacters "
                                 "(the unquoted-filename injection class, CWE-78)."),
                ))
                break
    return out


# --- detector 3: path traversal / sandbox escape ----------------------------------

async def _path_traversal(s, tool, cls, identity, canary_path, canary_body, real_file) -> list:
    if not cls["path"] or canary_path is None:
        return []
    payloads = [
        ("absolute", canary_path),
        ("traversal", "../../../../../../../../.." + canary_path),
    ]
    out = []
    for pp in cls["path"]:
        for label, payload in payloads:
            args = _fill_args(tool, pp, payload, real_file)
            try:
                resp = await s.call(tool["name"], args)
            except ToolError:
                continue
            if canary_body in _blob(resp):
                out.append(Finding(
                    probe_class="sink", severity="high",
                    title=f"Path traversal / sandbox escape on '{tool['name']}' via '{pp}' ({label})",
                    identity=identity,
                    repro={"tool": tool["name"], "arguments": args},
                    evidence={
                        "sink_param": pp, "payload": payload,
                        "escaped_to": canary_path,
                        "explanation": (f"The '{pp}' parameter reached a file OUTSIDE the intended "
                                        f"root -- Siege planted a canary there and its contents came "
                                        f"back. An {label} path is not confined to the workspace."),
                    },
                    remediation=("Canonicalize the path and verify it starts_with a fixed workspace "
                                 "root; reject absolute paths and `..` -- on EVERY build/mode "
                                 "(the sanitizer-compiled-out class, CWE-22: the guard existed but was "
                                 "compiled out of the default path)."),
                ))
                break
    return out


# --- orchestration ----------------------------------------------------------------

async def probe_sink(spec, canary_path=None, canary_body=None, real_file=None) -> list:
    """Run the server-side execution-sink detectors. Returns list[Finding].

    canary_path/canary_body: an out-of-sandbox file Siege planted (path traversal
    detector). When absent, that detector is skipped (honest degrade). SSRF lives
    in probe_sink_ssrf (needs a loopback listener) and is reported separately.

    real_file: a path that EXISTS in the target's input space, used to fill path
    params so a server that existence-checks inputs proceeds to the sink. An operator
    provides it for a target that resolves paths against a base dir (Node `path.join`
    ignores absolute segments, so the planted absolute canary won't satisfy it). When
    omitted, Siege falls back to the absolute canary (works for absolute-honoring
    servers) and plants one if needed.
    """
    own = False
    if real_file is None:
        real_file = canary_path
    if real_file is None:
        real_file, _ = plant_canary()
        own = True
    findings, seen = [], set()
    try:
        for ident in spec.identities:
            try:
                async with open_session(spec, ident.name) as s:
                    tools = await s.list_tools()
            except Exception:
                continue
            # Re-open per call set so a crashing tool doesn't poison the session.
            for tool in tools[:MAX_TOOLS]:
                cls = _classify(tool)
                if not (cls["exec"] or cls["path"] or cls["url"] or cls["invokes"]):
                    continue
                key = (tool["name"], ident.name)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    async with open_session(spec, ident.name) as s:
                        findings += await _allowlist_bypass(s, tool, cls, ident.name, real_file)
                        findings += await _param_injection(s, tool, cls, ident.name, real_file)
                        findings += await _path_traversal(s, tool, cls, ident.name,
                                                          canary_path, canary_body, real_file)
                except Exception:
                    continue
    finally:
        if own:
            with contextlib.suppress(OSError):
                os.unlink(real_file)
    return _dedup(findings)


def _dedup(findings) -> list:
    out, seen = [], set()
    for f in findings:
        k = (f.title, f.evidence.get("sink_param"))
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


# --- detector 4: SSRF (loopback canary listener) ----------------------------------

class _CanaryHTTP:
    """A one-shot loopback HTTP listener. If the target fetches its URL, the request
    lands here -- proof the server made an outbound request to an address it chose to
    trust (127.0.0.1). A safe fetcher blocks loopback/link-local/private ranges; one
    that reaches this canary reaches 169.254.169.254 by the same missing guard."""

    def __init__(self):
        self.hits: set = set()
        self.body = ("SIEGE-SSRF-" + secrets.token_hex(6))
        self._server = None
        self._thread = None
        self.port = None

    def start(self):
        hits, body = self.hits, self.body.encode()

        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):                       # noqa: N802
                hits.add(self.path.lstrip("/"))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):              # silence the default stderr spam
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def url(self, token: str) -> str:
        return f"http://127.0.0.1:{self.port}/{token}"

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()


async def probe_sink_ssrf(spec) -> tuple[list, bool, str]:
    """SSRF detector. Returns (findings, ran, skip_reason). `ran` is False (with a
    reason) when the loopback listener can't bind -- an honest not-tested, not a pass.
    Only flags a fetch we OBSERVED reach the canary, so a fetcher that blocks loopback
    (the fixed shape) produces nothing."""
    try:
        canary = _CanaryHTTP()
        canary.start()
    except OSError as e:
        return [], False, f"loopback listener could not bind ({e})"

    real_file, _ = plant_canary()
    findings, seen = [], set()
    try:
        for ident in spec.identities:
            try:
                async with open_session(spec, ident.name) as s:
                    tools = await s.list_tools()
            except Exception:
                continue
            for tool in tools[:MAX_TOOLS]:
                cls = _classify(tool)
                if not cls["url"]:
                    continue
                key = (tool["name"], ident.name)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    async with open_session(spec, ident.name) as s:
                        findings += await _ssrf_tool(s, tool, cls, ident.name, canary, real_file)
                except Exception:
                    continue
    finally:
        canary.stop()
        with contextlib.suppress(OSError):
            os.unlink(real_file)
    return _dedup(findings), True, ""


async def _ssrf_tool(s, tool, cls, identity, canary, real_file) -> list:
    out = []
    for up in cls["url"]:
        token = "t" + secrets.token_hex(5)
        args = _fill_args(tool, up, canary.url(token), real_file)
        try:
            resp = await s.call(tool["name"], args)
        except ToolError:
            resp = {}
        # The fetch may complete just after the call returns; poll briefly.
        hit = False
        for _ in range(15):
            if token in canary.hits or canary.body in _blob(resp):
                hit = True
                break
            await asyncio.sleep(0.1)
        if hit:
            out.append(Finding(
                probe_class="sink", severity="high",
                title=f"SSRF on '{tool['name']}' via '{up}': fetches an unvalidated loopback URL",
                identity=identity,
                repro={"tool": tool["name"], "arguments": args},
                evidence={
                    "sink_param": up, "fetched": canary.url(token),
                    "observed": "listener hit" if token in canary.hits else "canary body returned",
                    "explanation": ("The tool fetched a Siege-controlled loopback address with no host "
                                    "validation. A safe fetcher blocks loopback/link-local/private ranges; "
                                    "this one reaches 127.0.0.1 -- and by the same missing guard, "
                                    "169.254.169.254 (cloud metadata) and internal services."),
                },
                remediation=("Resolve the host and reject loopback, link-local (169.254.0.0/16), and private "
                             "ranges BEFORE fetching; re-validate after every redirect; do not follow "
                             "redirects to blocked ranges (the unvalidated-fetch class, CWE-918)."),
            ))
    return out

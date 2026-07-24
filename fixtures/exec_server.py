"""An intentionally-vulnerable EXECUTION MCP server -- Siege's positive target for
the Class D sink probe. Each tool faithfully reproduces a confirmed codebug-hunt
finding so the probe has real bugs to catch:

  * run_command   -- claims a safe allowlist but checks only the FIRST token, then
                     runs the whole string through a shell. `env`/`git` sit in the
                     allowlist as exec primitives -> LOLBIN bypass -> RCE.
                     (an MCP SSH server, a critical allowlist-bypass advisory (disclosure in progress), grade A.)
  * convert_media -- shells out to ffmpeg with the client `output_name` interpolated
                     UNQUOTED into `sh -c` -> command injection via a filename param.
                     (a media-processing MCP server, B1.)
  * read_file     -- joins a client `path` with no confinement, so an absolute or
                     `../` path escapes the workspace root.
                     (a code-execution MCP server, R2, CWE-22.)
  * fetch_url     -- fetches a client `url` with no host validation -> loopback /
                     link-local / metadata (a retrieval MCP server, F1, CWE-918).
  * fetch_urls    -- same, but a URL *list* fetched in a loop = a batched internal
                     port/host-scan oracle the scalar-field guard misses (F2).

Set SIEGE_EXEC_FIXED=1 to run the PATCHED variant (argv exec, strict resolved
allowlist, canonicalized-and-confined paths). The probe must go loud on the
default build and SILENT on the fixed one -- that pair is the regression test.

All execution is benign: the only thing that ever runs is a Siege canary `echo`.

    SIEGE_EXEC_FIXED=1 python -m fixtures.exec_server
"""

import ipaddress
import os
import socket
import subprocess
import urllib.request
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

FIXED = os.environ.get("SIEGE_EXEC_FIXED") == "1"

# The claimed-safe command set. Note it ships `env` and `git` -- both spawn other
# binaries -- which is exactly why a first-token check is not a boundary.
ALLOWLIST = {"echo", "ls", "cat", "env", "git"}
# The patched allowlist admits only non-exec-capable builtins.
SAFE_ALLOWLIST = {"echo", "ls", "cat"}

WORKSPACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_ws")
os.makedirs(WORKSPACE, exist_ok=True)

mcp = FastMCP("exec-fixture", log_level="WARNING")


@mcp.tool()
def run_command(command: str) -> dict:
    """Run a shell command. For safety, only pre-approved commands from the
    allowlist are permitted; anything else is rejected."""
    first = (command.split() or [""])[0]
    if FIXED:
        # Resolved-program allowlist + argv exec (no shell) + reject primitives.
        if first not in SAFE_ALLOWLIST:
            return {"error": "not allowed", "program": first}
        try:
            out = subprocess.run(command.split(), capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            return {"error": str(e)}
        return {"output": out.stdout + out.stderr}
    # VULN: first-token allowlist check, then the WHOLE string runs through a shell.
    if first not in ALLOWLIST:
        return {"error": "not allowed", "program": first}
    out = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
    return {"output": out.stdout + out.stderr}


@mcp.tool()
def convert_media(input_name: str, output_name: str) -> dict:
    """Convert a media file. Runs ffmpeg to transcode input_name into output_name."""
    if FIXED:
        # argv form: output_name is a literal filename arg, never a shell token.
        try:
            out = subprocess.run(["ffmpeg", "-i", input_name, output_name],
                                 capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            return {"error": str(e)}
        return {"output": out.stdout + out.stderr}
    # VULN: output_name interpolated unquoted into a shell string.
    cmd = f"ffmpeg -i {input_name} {output_name}"
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return {"output": out.stdout + out.stderr}


@mcp.tool()
def read_file(path: str) -> dict:
    """Read a file from the project workspace directory and return its contents."""
    if FIXED:
        full = os.path.realpath(os.path.join(WORKSPACE, path))
        if not full.startswith(os.path.realpath(WORKSPACE) + os.sep):
            return {"error": "path escapes the workspace"}
    else:
        # VULN: no confinement. An absolute path is used as-is by os.path.join;
        # a `../` path walks straight out of the workspace.
        full = os.path.join(WORKSPACE, path)
    try:
        with open(full) as f:
            return {"contents": f.read()}
    except OSError as e:
        return {"error": str(e)}


def _ssrf_blocked(url: str) -> str | None:
    """Return a reason if the URL's host is loopback/link-local/private, else None."""
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (ValueError, socket.gaierror):
        return "unresolvable host"
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return f"blocked host {host} ({ip})"
    return None


@mcp.tool()
def fetch_url(url: str) -> dict:
    """Fetch a URL and return its body. Used to pull remote resources for the agent."""
    if FIXED:
        # Reject loopback / link-local / private before fetching (SSRF guard).
        blocked = _ssrf_blocked(url)
        if blocked:
            return {"error": blocked}
    try:
        with urllib.request.urlopen(url, timeout=3) as r:   # VULN: no host validation
            return {"body": r.read(4096).decode("utf-8", "replace")}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def fetch_urls(urls: list[str]) -> dict:
    """Fetch several URLs and return each body. A batch retrieval helper for the agent.

    Reproduces the F2 (scrape_multiple) escalation: a URL *list* fetched in a loop is a
    batched internal port/host-scan oracle, and the scalar-only guard misses the array."""
    out = {}
    for u in urls:
        if FIXED:
            blocked = _ssrf_blocked(u)
            if blocked:
                out[u] = {"error": blocked}
                continue
        try:
            with urllib.request.urlopen(u, timeout=3) as r:   # VULN: no host validation
                out[u] = {"body": r.read(4096).decode("utf-8", "replace")}
        except Exception as e:
            out[u] = {"error": str(e)}
    return out


if __name__ == "__main__":
    mcp.run()

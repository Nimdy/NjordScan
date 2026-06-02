"""njordscan gui — a local web "scan studio".

Launches a localhost-only web UI to scan any target — a local folder, a git URL, or
a live URL (DAST) — and explore the findings + attack paths in the browser instead of
reading terminal output. Dependency-free (Python standard library only), so it ships
with the core package.

Safety by design:
  * binds to 127.0.0.1 by default — never exposed to the network;
  * scans run IN-PROCESS via the normal Orchestrator — NjordScan only *reads* a target,
    it never executes it (git clones are shallow and run no repo hooks);
  * live-URL scans use the same benign, SSRF-guarded DAST as the CLI (private/loopback
    hosts are refused unless you opt in).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

from .._webguard import is_local_request, strict_for

HERE = Path(__file__).resolve().parent
_MAX_BODY = 64 * 1024
_strict_local = True  # reject non-localhost Host; relaxed when bound to a non-local address


def _git_clone(url: str, dest: Path) -> None:
    """Shallow-clone a repo for scanning. No submodules, no hooks — read-only intent."""
    subprocess.run(
        ["git", "clone", "--depth", "1", "--no-tags", "--", url, str(dest)],
        check=True, capture_output=True, timeout=180,
    )


def run_scan(target: str, mode: str, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a target and return the JSON report dict (or {'error': ...})."""
    from ..core.config import Config
    from ..core.orchestrator import Orchestrator
    from ..report.json_report import build_report

    target = (target or "").strip()
    if not target:
        return {"error": "Enter a target to scan."}

    tmp_dir: Path | None = None
    try:
        if mode == "url":
            tmp_dir = Path(tempfile.mkdtemp(prefix="njord-gui-url-"))
            cfg = Config(target=tmp_dir, url=target, allow_private=bool(opts.get("allow_private")))
        elif mode == "git":
            tmp_dir = Path(tempfile.mkdtemp(prefix="njord-gui-clone-"))
            try:
                _git_clone(target, tmp_dir)
            except subprocess.CalledProcessError as exc:
                return {"error": f"git clone failed: {exc.stderr.decode('utf-8', 'replace')[:300]}"}
            except FileNotFoundError:
                return {"error": "git is not installed — needed to scan a git URL."}
            except subprocess.TimeoutExpired:
                return {"error": "git clone timed out (3 min)."}
            cfg = Config(target=tmp_dir)
        else:  # local path
            path = Path(target).expanduser()
            if not path.exists():
                return {"error": f"Path not found: {path}"}
            if not path.is_dir():
                return {"error": f"Not a folder: {path}"}
            cfg = Config(target=path.resolve())

        result = asyncio.run(Orchestrator(cfg).run())
        report = build_report(result)
        report["target_input"] = target
        report["mode"] = mode
        return report
    except Exception as exc:  # noqa: BLE001 — the studio must never crash the server
        return {"error": f"{type(exc).__name__}: {exc}"}
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if not is_local_request(self, strict_local=_strict_local):
            return self._send(403, b"forbidden", "text/plain")
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                body = (HERE / "index.html").read_bytes()
            except OSError:
                body = b"<h1>gui index.html missing</h1>"
            return self._send(200, body, "text/html; charset=utf-8")
        if path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    def do_POST(self) -> None:  # noqa: N802
        if not is_local_request(self, strict_local=_strict_local):
            return self._send(403, b"forbidden", "text/plain")
        if self.path.split("?", 1)[0] != "/api/scan":
            return self._send(404, b"not found", "text/plain")
        try:
            length = min(int(self.headers.get("Content-Length", 0)), _MAX_BODY)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._send(400, b'{"error":"bad request"}', "application/json")
        report = run_scan(
            str(payload.get("target", "")),
            str(payload.get("mode", "path")),
            payload.get("options") or {},
        )
        self._send(200, json.dumps(report).encode("utf-8"), "application/json")


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    global _strict_local
    _strict_local = strict_for(host)  # enforce localhost-only Host unless user bound elsewhere
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    print(f"🛡️  njordscan gui — scan studio at {url}")
    print("   Point it at a folder, a git URL, or a live URL. Ctrl-C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
        httpd.shutdown()

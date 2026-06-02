"""njordscan monitor — the operational dashboard server.

A localhost web app + a background scheduler. Register projects (folder / git URL /
live URL); the scheduler re-scans each on its interval; the UI shows each project's
current posture, the trend over time, and an alert feed when a new critical/high
appears. Dependency-free (standard library only); all state under ~/.njordscan/monitor.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

from . import scanner, store
from ..core.history import compare

HERE = Path(__file__).resolve().parent
_MAX_BODY = 64 * 1024

_scanning: set = set()
_lock = threading.Lock()
_stop = threading.Event()


def _do_scan(pid: str) -> None:
    proj = store.get_project(pid)
    if not proj:
        return
    with _lock:
        if pid in _scanning:
            return
        _scanning.add(pid)
    try:
        scanner.scan_project(proj)
    finally:
        with _lock:
            _scanning.discard(pid)


def _due(proj: Dict[str, Any]) -> bool:
    last = proj.get("last_scan")
    if not last:
        return True
    try:
        dt = datetime.fromisoformat(last)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    age_min = (datetime.now(timezone.utc) - dt).total_seconds() / 60.0
    return age_min >= float(proj.get("interval_minutes", 1440))


def _scheduler_loop() -> None:
    # give the server a moment to come up, then run due scans sequentially forever
    _stop.wait(3)
    while not _stop.is_set():
        for proj in store.list_projects():
            if _stop.is_set():
                break
            if _due(proj):
                _do_scan(proj["id"])
        _stop.wait(30)


def build_state() -> Dict[str, Any]:
    projects = []
    for p in store.list_projects():
        snaps = store.list_snapshots(p["id"])
        latest = snaps[-1] if snaps else None
        prev = snaps[-2] if len(snaps) >= 2 else None
        diff = None
        if latest is not None and prev is not None:
            d = compare(prev, latest)
            diff = {"new": len(d.new), "fixed": len(d.fixed)}
        projects.append({
            "id": p["id"], "name": p.get("name", ""), "target": p.get("target", ""),
            "mode": p.get("mode", "path"), "interval_minutes": p.get("interval_minutes", 1440),
            "last_scan": p.get("last_scan"), "last_status": p.get("last_status", ""),
            "counts": latest.counts if latest else {}, "total": latest.total if latest else 0,
            "trend": [{"ts": s.timestamp, "total": s.total} for s in snaps[-40:]],
            "scans": len(snaps), "diff": diff,
            "scanning": p["id"] in _scanning,
        })
    return {"ts": datetime.now(timezone.utc).isoformat(), "projects": projects,
            "alerts": store.list_alerts(60)}


def project_detail(pid: str) -> Dict[str, Any]:
    proj = store.get_project(pid)
    if not proj:
        return {"error": "no such project"}
    snaps = store.list_snapshots(pid)
    latest = snaps[-1] if snaps else None
    prev = snaps[-2] if len(snaps) >= 2 else None
    d = compare(prev, latest) if (latest and prev) else None
    return {
        "project": proj,
        "timeline": [{"ts": s.timestamp, "total": s.total, "counts": s.counts} for s in snaps],
        "findings": sorted(latest.findings, key=lambda f: f.get("severity", "")) if latest else [],
        "diff": {"new": d.new, "fixed": d.fixed} if d else None,
    }


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _body(self) -> Dict[str, Any]:
        try:
            n = min(int(self.headers.get("Content-Length", 0)), _MAX_BODY)
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    def do_GET(self) -> None:  # noqa: N802
        path, _, qs = self.path.partition("?")
        if path in ("/", "/index.html"):
            try:
                return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            except OSError:
                return self._send(200, b"<h1>monitor index.html missing</h1>", "text/html")
        if path == "/api/state":
            return self._json(build_state())
        if path == "/api/project":
            pid = dict(p.split("=", 1) for p in qs.split("&") if "=" in p).get("id", "")
            return self._json(project_detail(pid))
        if path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        body = self._body()
        if path == "/api/add":
            proj = store.add_project(
                target=str(body.get("target", "")), mode=str(body.get("mode", "path")),
                name=str(body.get("name", "")), interval_minutes=int(body.get("interval_minutes", 1440)),
            )
            threading.Thread(target=_do_scan, args=(proj["id"],), daemon=True).start()  # first scan now
            return self._json({"ok": True, "project": proj})
        if path == "/api/scan":
            pid = str(body.get("id", ""))
            threading.Thread(target=_do_scan, args=(pid,), daemon=True).start()
            return self._json({"ok": True})
        if path == "/api/remove":
            store.remove_project(str(body.get("id", "")))
            return self._json({"ok": True})
        return self._send(404, b"not found", "text/plain")


def run(host: str = "127.0.0.1", port: int = 8770, open_browser: bool = True) -> None:
    store.monitor_dir().mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    url = f"http://{host}:{port}"
    print(f"🛡️  njordscan monitor — operational dashboard at {url}")
    print(f"   Watching {len(store.list_projects())} project(s). Ctrl-C to stop. State: {store.monitor_dir()}")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    httpd = ThreadingHTTPServer((host, port), _Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
        _stop.set()
        httpd.shutdown()

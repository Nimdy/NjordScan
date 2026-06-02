#!/usr/bin/env python3
"""Bring-Your-Own-Target logging reverse proxy.

The lab's blue team detects attacks by reading a JSON access log. The built-in
targets write that log themselves — but YOUR app doesn't. This proxy fixes that:
point it at any target (``TARGET_URL``) and it transparently forwards every request
while writing the same blue-team LOG CONTRACT for each one. Now the blue team (and
the dashboard) work against *any* app, with no changes to the app.

    TARGET_URL=http://host.docker.internal:3000 python3 proxy.py   # proxy :8080 -> your app

Dependency-free (Python standard library only). It forwards method, path, query,
headers and body, returns the upstream response unchanged, and logs to
<LOG_DIR>/byo.log (svc="byo"). It does NOT modify traffic — it only observes.
Only proxy apps you own or are authorized to test.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TARGET_URL = os.environ.get("TARGET_URL", "").rstrip("/")
PORT = int(os.environ.get("PORT", "8080"))
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
SVC = os.environ.get("SVC", "byo")
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host"}

try:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
except OSError:
    pass


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(method: str, path: str, query: str, status: int, ua: str, ref: str, body: str, ip: str) -> None:
    try:
        line = json.dumps({
            "ts": _now(), "svc": SVC, "ip": ip, "method": method,
            "path": path, "query": query, "status": status, "ua": ua,
            "ref": ref, "body": (body or "")[:500],
        })
        with open(os.path.join(LOG_DIR, SVC + ".log"), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass  # logging must never break the proxy


class _Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):  # quiet
        pass

    def _handle(self) -> None:
        method = self.command
        full = self.path                      # /path?query
        path, _, query = full.partition("?")
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        ip = self.headers.get("x-forwarded-for") or (self.client_address[0] if self.client_address else "")
        ua = self.headers.get("user-agent", "")
        ref = self.headers.get("referer", "")

        if not TARGET_URL:
            self._respond(502, b"byo-proxy: TARGET_URL is not set", "text/plain")
            _log(method, path, query, 502, ua, ref, body.decode("utf-8", "replace"), ip)
            return

        # forward to the upstream, preserving method/headers/body
        fwd_headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}
        req = urllib.request.Request(TARGET_URL + full, data=body or None, method=method, headers=fwd_headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                status = resp.status
                payload = resp.read()
                resp_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in _HOP_BY_HOP]
        except urllib.error.HTTPError as e:                # upstream returned 4xx/5xx — pass it through
            status = e.code
            payload = e.read()
            resp_headers = [(k, v) for k, v in e.headers.items() if k.lower() not in _HOP_BY_HOP]
        except Exception as e:                              # noqa: BLE001 — upstream unreachable
            status = 502
            payload = f"byo-proxy: upstream error: {e}".encode("utf-8")
            resp_headers = [("Content-Type", "text/plain")]

        self._respond(status, payload, headers=resp_headers)
        _log(method, path, query, status, ua, ref, body.decode("utf-8", "replace"), ip)

    def _respond(self, status: int, body: bytes, ctype: str = "", headers=None) -> None:
        try:
            self.send_response(status)
            if headers is None:
                headers = [("Content-Type", ctype or "text/plain")]
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


def main() -> int:
    if not TARGET_URL:
        print("byo-proxy: set TARGET_URL=http://your-app:PORT (proxy will refuse traffic until then)", file=sys.stderr)
    print(f"[byo-proxy] :{PORT}  ->  {TARGET_URL or '(unset)'}   logging to {LOG_DIR}/{SVC}.log", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), _Proxy).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

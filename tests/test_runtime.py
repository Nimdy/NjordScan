"""Dynamic (DAST) detector tests against a local in-process server."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from conftest import CLEAN_APP, scan

pytestmark = pytest.mark.asyncio


class _Vuln(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if "next" in q:  # open redirect
            self.send_response(302)
            self.send_header("Location", q["next"][0])
            self.end_headers()
            return
        if u.path == "/api/chat":  # unauth AI endpoint (JSON)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"choices":[{"message":{"content":"hi"}}]}')
            return
        if "njordscan-nonexistent" in u.path:  # verbose error
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Error: boom\n    at Object.<anonymous> (/app/node_modules/x.js:42)")
            return
        body = q.get("njordscan", [""])[0]  # reflect input (XSS)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=abc; Path=/")  # missing flags
        self.send_header("X-Powered-By", "Next.js 14.2.5")
        self.end_headers()
        self.wfile.write(f"<html>hi {body}</html>".encode())


@pytest.fixture
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


async def test_ssrf_guard_blocks_loopback_by_default(vuln_server):
    result = await scan(CLEAN_APP, only_detectors=["runtime"], url=vuln_server)  # allow_private defaults False
    assert result.total == 0  # refused to scan loopback


async def test_dynamic_scan_finds_runtime_issues(vuln_server):
    result = await scan(CLEAN_APP, only_detectors=["runtime"], url=vuln_server, allow_private=True)
    ids = {f.rule_id for f in result.findings}
    assert "headers.missing-csp" in ids
    assert "dast.open-redirect" in ids
    assert "dast.reflected-xss" in ids
    assert "cookie.insecure-flags-live" in ids
    assert "ai-endpoint.unauthenticated-live" in ids


async def test_ai_endpoint_precision_requires_api_response(vuln_server):
    """Only the JSON /api/chat should flag — not HTML app-shell routes."""
    result = await scan(CLEAN_APP, only_detectors=["runtime"], url=vuln_server, allow_private=True)
    ai = [f for f in result.findings if f.rule_id == "ai-endpoint.unauthenticated-live"]
    assert len(ai) == 1
    assert ai[0].file.endswith("/api/chat")

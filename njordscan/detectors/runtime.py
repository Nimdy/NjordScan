"""Dynamic (DAST) detector — probes a LIVE app via ``--url``.

This restores the dynamic dimension: it talks to a running server and checks the
things you can only see at runtime — real response headers, cookie flags, reflected
XSS, open redirects, verbose errors, and exposed AI endpoints.

Safety (a security tool must be safe to point at things):
  - **TLS verification stays ON** (V1 disabled it globally — we never do).
  - **SSRF-safe**: refuses private/loopback/link-local hosts unless ``--allow-private``,
    so it can't be turned into an internal-network scanner.
  - **Non-invasive**: only benign, idempotent probes. It never sends real attack
    payloads that could change state, and never POSTs to AI endpoints (which could
    cost you money) — it only checks whether they answer unauthenticated.
  - Never raises; degrades to no findings if the host is unreachable.

Requires the optional ``[dynamic]`` extra (httpx); install with ``pip install 'njordscan[dynamic]'``.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List
from urllib.parse import urlparse, urlsplit, urlunsplit

from ..core.finding import Finding
from ..core.project import Project
from .base import Detector

logger = logging.getLogger(__name__)

_UA = "njordscan-dynamic/2.0 (+https://github.com/nimdy/njordscan)"
_XSS_MARKER = "njq9z<x>\"'"          # distinctive; the <> would be escaped if handled safely
_REDIRECT_TARGET = "http://njordscan.invalid/redirect-probe"   # invalid TLD: never actually fetched
_REDIRECT_PARAMS = ("next", "url", "redirect", "redirect_uri", "return", "returnTo", "to", "dest", "continue")
_AI_PATHS = ("/api/chat", "/api/ai", "/api/completion", "/api/completions",
             "/api/generate", "/api/assistant", "/api/copilot", "/api/llm", "/api/agent")
_STACK_MARKERS = ("Traceback (most recent call last)", "    at ", "\n  at Object.",
                  "Error:", "ENOENT", "node_modules", ".js:", "stack:")


class DynamicScanDetector(Detector):
    id = "runtime"
    name = "Dynamic scan (DAST)"
    kind = "dynamic"

    def applies(self, project: Project) -> bool:
        return bool(project.config.url)

    async def scan(self, project: Project) -> List[Finding]:
        url = (project.config.url or "").strip()
        if not url:
            return []
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            logger.warning("runtime: invalid --url %r (need http(s)://host)", url)
            return []

        if not project.config.allow_private and _is_private_host(parsed.hostname):
            logger.warning("runtime: refusing to scan private/loopback host %s (use --allow-private)",
                           parsed.hostname)
            return []

        try:
            import httpx  # noqa: PLC0415 — optional [dynamic] extra
        except ImportError:
            logger.warning("runtime: dynamic scanning needs `pip install 'njordscan[dynamic]'`")
            return []

        findings: List[Finding] = []
        timeout = project.config.dynamic_timeout
        try:
            async with httpx.AsyncClient(
                verify=True, timeout=timeout, follow_redirects=False,
                headers={"User-Agent": _UA}, limits=httpx.Limits(max_connections=8),
            ) as client:
                base = await self._safe_get(client, url)
                if base is not None:
                    findings += self._check_headers(base, url)
                    findings += self._check_cookies(base, url)
                findings += await self._check_open_redirect(client, url)
                findings += await self._check_verbose_error(client, url)
                findings += await self._check_ai_endpoints(client, url)
        except Exception as exc:  # noqa: BLE001 — never let dynamic scanning crash the run
            logger.warning("runtime: dynamic scan error: %s", exc)
        return findings

    async def _safe_get(self, client, url, **kw):
        try:
            return await client.get(url, **kw)
        except Exception as exc:  # noqa: BLE001
            logger.debug("runtime GET %s failed: %s", url, exc)
            return None

    # -- checks --------------------------------------------------------------

    def _check_headers(self, resp, url: str) -> List[Finding]:
        h = {k.lower(): v for k, v in resp.headers.items()}
        out: List[Finding] = []

        def miss(rule_id: str, msg: str, conf: str = "high") -> None:
            out.append(Finding(rule_id=rule_id, file=url, line=0, detector=self.id,
                               confidence=conf, message=msg))

        if "content-security-policy" not in h:
            miss("headers.missing-csp", "Response has no Content-Security-Policy header.")
        if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
            miss("headers.missing-hsts", "HTTPS response has no Strict-Transport-Security header.")
        csp = h.get("content-security-policy", "")
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            miss("headers.missing-x-frame-options", "No X-Frame-Options or CSP frame-ancestors (clickjacking).")
        if h.get("x-content-type-options", "").lower() != "nosniff":
            miss("headers.missing-x-content-type-options", "No X-Content-Type-Options: nosniff.", "medium")
        if "referrer-policy" not in h:
            miss("headers.missing-referrer-policy", "No Referrer-Policy header.", "medium")
        banner = h.get("x-powered-by") or h.get("server")
        if banner and any(c.isdigit() for c in banner):
            miss("headers.server-version-disclosure", f"Response discloses software/version: {banner!r}.", "medium")
        return out

    def _check_cookies(self, resp, url: str) -> List[Finding]:
        out: List[Finding] = []
        for raw in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
            low = raw.lower()
            name = raw.split("=", 1)[0].strip()
            missing = [f for f, tok in (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
                       if tok not in low]
            if missing:
                out.append(Finding(
                    rule_id="cookie.insecure-flags-live", file=url, line=0, detector=self.id,
                    confidence="medium", message=f"Cookie '{name}' set without: {', '.join(missing)}.",
                ))
        return out

    async def _check_open_redirect(self, client, url: str) -> List[Finding]:
        out: List[Finding] = []
        parts = urlsplit(url)
        for param in _REDIRECT_PARAMS:
            probe = urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                                f"{param}={_REDIRECT_TARGET}", ""))
            resp = await self._safe_get(client, probe)
            if resp is None:
                continue
            loc = resp.headers.get("location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and loc.startswith(_REDIRECT_TARGET):
                out.append(Finding(
                    rule_id="dast.open-redirect", file=probe, line=0, detector=self.id,
                    confidence="high", message=f"`{param}` parameter redirects to an external URL.",
                ))
                break  # one is enough
        # reflected-XSS probe reuses the same client
        out += await self._probe_reflection(client, url)
        return out

    async def _probe_reflection(self, client, url: str) -> List[Finding]:
        parts = urlsplit(url)
        probe = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", f"njordscan={_XSS_MARKER}", ""))
        resp = await self._safe_get(client, probe)
        if resp is None:
            return []
        ctype = resp.headers.get("content-type", "")
        if "html" in ctype and _XSS_MARKER in resp.text:
            return [Finding(
                rule_id="dast.reflected-xss", file=probe, line=0, detector=self.id,
                confidence="high", message="A URL parameter is reflected into the HTML unescaped.",
            )]
        return []

    async def _check_verbose_error(self, client, url: str) -> List[Finding]:
        parts = urlsplit(url)
        probe = urlunsplit((parts.scheme, parts.netloc,
                            (parts.path.rstrip("/") + "/njordscan-nonexistent-%27%22"), "", ""))
        resp = await self._safe_get(client, probe)
        if resp is None:
            return []
        body = resp.text[:5000]
        if resp.status_code >= 500 and any(m in body for m in _STACK_MARKERS):
            return [Finding(
                rule_id="dast.verbose-error", file=probe, line=0, detector=self.id,
                confidence="medium", message=f"Server returned a verbose error/stack trace (HTTP {resp.status_code}).",
            )]
        return []

    async def _check_ai_endpoints(self, client, url: str) -> List[Finding]:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        out: List[Finding] = []
        for path in _AI_PATHS:
            resp = await self._safe_get(client, origin + path)
            if resp is None:
                continue
            ctype = resp.headers.get("content-type", "").lower()
            # Require a real API-shaped response (JSON / SSE), not an HTML app-shell —
            # SPAs/Next.js often return 200 HTML for unknown routes, which is NOT an AI endpoint.
            api_shaped = ("application/json" in ctype or "text/event-stream" in ctype
                          or "application/x-ndjson" in ctype)
            # 401/403 = protected (good). 404 = absent. Flag only an unauth'd API-shaped answer.
            if resp.status_code in (200, 400, 405) and (api_shaped or resp.status_code == 405):
                out.append(Finding(
                    rule_id="ai-endpoint.unauthenticated-live", file=origin + path, line=0, detector=self.id,
                    confidence="medium" if resp.status_code == 200 else "low",
                    message=(f"AI endpoint {path} answered HTTP {resp.status_code} ({ctype or 'no content-type'}) "
                             "without auth — verify it requires login + rate limiting (denial-of-wallet risk)."),
                ))
        return out


def _is_private_host(host: str) -> bool:
    """True if the host resolves to a private/loopback/link-local/reserved address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # unresolvable — the request will simply fail, no SSRF risk
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return True
    return False

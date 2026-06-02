"""Localhost / CSRF guard for the bundled local web tools (`gui`, `monitor`).

These bind to localhost and have no auth, so two browser-based attacks matter even
though the server is "local":

  * CSRF — a malicious page you visit could `fetch()` a state-changing POST
    (run a scan, register/clone a project) at http://127.0.0.1:PORT. A cross-origin
    POST carries an ``Origin`` header that won't match ours, so we reject it.
  * DNS rebinding — an attacker domain re-resolved to 127.0.0.1 could talk to the
    server with its own Host header. We only answer requests whose Host is localhost
    (unless the user deliberately bound to a non-local address).

GET reads are already protected by the same-origin policy (we send no CORS headers,
so a cross-site page can't read the response); we still apply the Host check to them.
"""

from __future__ import annotations

_LOCAL_HOSTNAMES = {"127.0.0.1", "localhost", "::1", ""}


def is_local_request(handler, *, strict_local: bool = True) -> bool:
    """True if the request is safe to serve. Rejects non-local Host (rebinding) and
    cross-origin state changes (CSRF). ``strict_local=False`` when the server was
    intentionally bound to a non-localhost address (the user opted into exposure)."""
    if strict_local:
        host = (handler.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in _LOCAL_HOSTNAMES:
            return False
    origin = handler.headers.get("Origin")
    if origin:
        own = handler.headers.get("Host", "")
        if origin.rstrip("/") not in (f"http://{own}", f"https://{own}"):
            return False
    return True


def strict_for(host: str) -> bool:
    """Whether to enforce the localhost-only Host check, given the bind address."""
    return (host or "").strip() in {"127.0.0.1", "localhost", "::1", ""}

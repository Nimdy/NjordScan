"""The localhost / CSRF guard shared by the bundled web tools (gui, monitor).

A malicious page you visit could try to drive the local server (run a scan, register a
project) via a cross-origin POST, or reach it via DNS rebinding. The guard rejects both
while leaving the legitimate same-origin UI — and non-browser clients like curl — working.
"""

from __future__ import annotations

from njordscan._webguard import is_local_request, strict_for


class _FakeHandler:
    def __init__(self, **headers):
        self.headers = headers


def test_same_origin_allowed():
    assert is_local_request(_FakeHandler(Host="127.0.0.1:8770", Origin="http://127.0.0.1:8770"))


def test_no_origin_allowed():
    # browser navigations and non-browser clients (curl, tests) send no Origin
    assert is_local_request(_FakeHandler(Host="127.0.0.1:8770"))
    assert is_local_request(_FakeHandler())


def test_cross_origin_post_rejected():  # classic CSRF
    assert not is_local_request(_FakeHandler(Host="127.0.0.1:8770", Origin="http://evil.example"))


def test_non_local_host_rejected():  # DNS rebinding: attacker domain → 127.0.0.1
    assert not is_local_request(_FakeHandler(Host="evil.example", Origin="http://evil.example"))


def test_localhost_and_ipv6_hostnames_ok():
    assert is_local_request(_FakeHandler(Host="localhost:8765", Origin="http://localhost:8765"))
    assert is_local_request(_FakeHandler(Host="[::1]:8765"))


def test_relaxed_when_bound_non_local():
    # user deliberately bound to 0.0.0.0: Host check relaxed, CSRF check still enforced
    assert is_local_request(_FakeHandler(Host="192.168.1.5:8770"), strict_local=False)
    assert not is_local_request(
        _FakeHandler(Host="192.168.1.5:8770", Origin="http://evil.example"), strict_local=False
    )


def test_strict_for_bind_host():
    assert strict_for("127.0.0.1") and strict_for("localhost") and strict_for("")
    assert not strict_for("0.0.0.0")

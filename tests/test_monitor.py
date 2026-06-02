"""njordscan monitor — the operational dashboard's registry, snapshots, and alerts.

Covers the core loop: register a project, scan it (snapshot recorded), re-scan it (the
diff-over-time must NOT re-alert persistent findings), and the state shape the UI reads.
Everything is isolated to a temp NJORDSCAN_HOME so it never touches real user data.
"""

from __future__ import annotations

from njordscan.monitor import scanner, server, store

from conftest import VULN_APP


def test_register_scan_snapshot_and_alert_on_new(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path / "home"))

    p = store.add_project(str(VULN_APP), mode="path", name="vuln", interval_minutes=60)
    assert p["id"] and store.get_project(p["id"])["name"] == "vuln"
    assert len(store.list_projects()) == 1

    # first scan: a snapshot is recorded and existing criticals surface as alerts
    r = scanner.scan_project(p)
    assert r["ok"] and r["total"] >= 1
    snap = store.latest_snapshot(p["id"])
    assert snap is not None and snap.total == r["total"]
    first_alerts = len(store.list_alerts())

    # re-scan the SAME code: nothing new -> no new alerts (no false re-alerting)
    scanner.scan_project(store.get_project(p["id"]))
    assert len(store.list_snapshots(p["id"])) == 2
    assert len(store.list_alerts()) == first_alerts

    # the state shape the dashboard UI consumes
    st = server.build_state()
    proj = st["projects"][0]
    assert proj["diff"] == {"new": 0, "fixed": 0}
    assert proj["scans"] == 2
    assert proj["counts"].get("critical", 0) >= 1


def test_bad_path_is_recorded_not_raised(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path / "home"))
    p = store.add_project("/no/such/dir/xyz-njord", mode="path")
    r = scanner.scan_project(p)
    assert not r["ok"]


def test_remove_project(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path / "home"))
    p = store.add_project(str(VULN_APP), mode="path")
    store.remove_project(p["id"])
    assert store.list_projects() == []

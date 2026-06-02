"""njordscan gui — the scan-studio scan runner.

Exercises the in-process scan runner that backs the web studio: a local-path scan
returns the same JSON report shape the CLI/JSON reporter produces, and bad input
degrades to a clean {'error': ...} instead of crashing the server.
"""

from __future__ import annotations

from njordscan.gui.server import run_scan

from conftest import VULN_APP


def test_gui_scan_local_path_returns_report():
    rep = run_scan(str(VULN_APP), "path", {})
    assert "error" not in rep, rep.get("error")
    assert rep["summary"]["total"] >= 1
    assert rep["findings"], "a deliberately-vulnerable app must produce findings"
    assert "attack_paths" in rep
    assert rep["mode"] == "path"
    # every finding carries the fields the UI renders
    f = rep["findings"][0]
    for key in ("rule_id", "severity", "title"):
        assert key in f


def test_gui_scan_bad_path_errors_gracefully():
    rep = run_scan("/no/such/path/xyz-njord", "path", {})
    assert "error" in rep and "not found" in rep["error"].lower()


def test_gui_scan_empty_target_errors():
    rep = run_scan("   ", "path", {})
    assert "error" in rep

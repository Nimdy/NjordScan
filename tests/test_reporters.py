"""Reporter output tests: JSON shape and SARIF validity."""

from __future__ import annotations

import json

import pytest

from njordscan.report.json_report import build_report
from njordscan.report.sarif import build_sarif

from conftest import scan

pytestmark = pytest.mark.asyncio


async def test_json_report_shape(vuln_app):
    result = await scan(vuln_app)
    report = build_report(result)
    assert report["tool"] == "njordscan"
    assert report["summary"]["total"] == result.total
    assert set(report["summary"]["by_severity"]) == {"critical", "high", "medium", "low", "info"}
    # round-trips as JSON
    json.loads(json.dumps(report))
    for f in report["findings"]:
        assert f["rule_id"] and f["severity"] and "fingerprint" in f


async def test_sarif_is_valid_2_1_0(vuln_app):
    result = await scan(vuln_app)
    sarif = build_sarif(result)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "NjordScan"
    assert run["tool"]["driver"]["rules"], "SARIF must include rule metadata"
    assert len(run["results"]) == result.total
    for r in run["results"]:
        assert r["level"] in {"error", "warning", "note"}
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


async def test_sarif_includes_taint_codeflow(vuln_app):
    result = await scan(vuln_app, only_detectors=["taint"])
    sarif = build_sarif(result)
    results = sarif["runs"][0]["results"]
    assert any("codeFlows" in r for r in results), "taint findings should export SARIF code flows"

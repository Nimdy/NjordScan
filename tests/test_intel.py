"""MITRE ATT&CK, SBOM, scan history, and exploit-intel (KEV/EPSS)."""

from __future__ import annotations

import json
import os
import shutil

import pytest

from njordscan.core.config import Config
from njordscan.core.finding import Finding
from njordscan.core.project import Project
from njordscan.knowledge import all_rules, enrich
from njordscan.knowledge.attack import techniques_for, technique

from conftest import VULN_APP, scan


# --- MITRE ATT&CK ---

def test_every_rule_maps_to_attack():
    unmapped = [r.id for r in all_rules() if not techniques_for(r.id)]
    assert not unmapped, f"rules without ATT&CK mapping: {unmapped}"


def test_finding_carries_attack_techniques():
    f = enrich(Finding(rule_id="injection.command", file="x.js", line=1))
    assert f.attack
    assert all(t.startswith("T") for t in f.attack)
    assert technique(f.attack[0]).tactic  # catalog has a tactic for it


@pytest.mark.asyncio
async def test_attack_navigator_layer(vuln_app):
    from njordscan.report.attack_navigator import build_layer

    result = await scan(vuln_app)
    layer = build_layer(result)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["techniques"]
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T") and t["score"] >= 1


# --- SBOM ---

def test_sbom_cyclonedx_and_spdx():
    from njordscan.sbom import to_cyclonedx, to_spdx

    proj = Project.load(Config(target=VULN_APP))
    cdx = to_cyclonedx(proj)
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    names = {c["name"] for c in cdx["components"]}
    assert "lodash" in names and "next" in names
    # seed advisories flag lodash/next -> SBOM correlates vulnerabilities
    assert cdx["vulnerabilities"]
    assert any(v["affects"][0]["ref"].startswith("pkg:npm/lodash@") for v in cdx["vulnerabilities"])

    spdx = to_spdx(proj)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["packages"] and spdx["relationships"]


# --- scan history ---

@pytest.mark.asyncio
async def test_history_record_list_compare(tmp_path):
    from njordscan.core.history import compare, list_snapshots, record

    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    r1 = await scan(work)
    record(r1)
    (work / "components" / "Comment.jsx").unlink()   # remove the dangerouslySetInnerHTML finding
    r2 = await scan(work)
    record(r2)

    snaps = list_snapshots(work)
    assert len(snaps) == 2
    diff = compare(snaps[0], snaps[1])
    assert any(f["rule_id"] == "xss.dangerously-set-inner-html" for f in diff.fixed)
    assert diff.persistent  # most findings remain


# --- exploit intelligence (CISA KEV + EPSS) ---

def test_kev_and_epss_loader(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path))
    from njordscan.core import exploit

    exploit._load.cache_clear()
    (tmp_path / "exploit.json").write_text(json.dumps({
        "kev": ["CVE-2019-10744"], "epss": {"CVE-2019-10744": 0.9},
    }))
    exploit._load.cache_clear()
    try:
        assert exploit.is_kev("CVE-2019-10744")
        assert not exploit.is_kev("CVE-0000-0000")
        assert exploit.epss_for("CVE-2019-10744") == 0.9
    finally:
        exploit._load.cache_clear()


@pytest.mark.asyncio
async def test_kev_bumps_dependency_to_critical(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path))
    from njordscan.core import exploit
    from njordscan.detectors import dependencies as deps

    # KEV-flag lodash's CVE; use seed advisories (empty NJORDSCAN_HOME cache).
    exploit._load.cache_clear()
    deps._load_advisories.cache_clear()
    (tmp_path / "exploit.json").write_text(json.dumps({"kev": ["CVE-2019-10744"], "epss": {}}))
    exploit._load.cache_clear()
    try:
        result = await scan(VULN_APP, only_detectors=["dependencies"])
        kev_findings = [f for f in result.findings if f.metadata.get("cisa_kev")]
        assert kev_findings, "expected a CISA-KEV-flagged dependency finding"
        assert all(f.effective_severity.value == "critical" for f in kev_findings)
        assert any("ACTIVELY EXPLOITED" in f.message for f in kev_findings)
    finally:
        exploit._load.cache_clear()
        deps._load_advisories.cache_clear()

"""Tests for baseline, config file, autofix, and HTML reporting."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from njordscan.core.baseline import Baseline, write_baseline
from njordscan.core.configfile import STARTER, load_config_file
from njordscan.fix import apply_fixes
from njordscan.report.html import render_html

from conftest import VULN_APP, scan

# asyncio_mode=auto handles async tests; this file mixes sync + async, so no module mark.


# --- baseline ---

async def test_baseline_hides_known_and_surfaces_new(tmp_path):
    result = await scan(VULN_APP)
    bl_path = tmp_path / "baseline.json"
    n = write_baseline(bl_path, result.findings)
    assert n == len({f.fingerprint for f in result.findings})

    new, known = Baseline.load(bl_path).partition(result.findings)
    assert new == [] and len(known) == result.total  # everything baselined

    # a fabricated new finding is NOT in the baseline
    extra = result.findings[0]
    extra.line = 99999
    new2, _ = Baseline.load(bl_path).partition([extra])
    assert len(new2) == 1


# --- config file ---

def test_config_file_round_trip(tmp_path):
    cfg = tmp_path / ".njordscan.yml"
    cfg.write_text(
        "min_severity: medium\nfail_on: high\n"
        "disable_rules: [crypto.weak-hash]\nseverity:\n  react.unsafe-target-blank: high\n"
    )
    fc = load_config_file(cfg)
    assert fc.min_severity == "medium"
    assert fc.fail_on == "high"
    assert "crypto.weak-hash" in fc.disable_rules
    assert fc.severity["react.unsafe-target-blank"] == "high"


def test_starter_config_is_valid_yaml():
    import yaml
    assert isinstance(yaml.safe_load(STARTER), dict)


async def test_disabled_rules_and_severity_override(tmp_path):
    base = await scan(VULN_APP)
    assert any(f.rule_id == "supply-chain.missing-lockfile" for f in base.findings)

    tuned = await scan(
        VULN_APP,
        disabled_rules={"supply-chain.missing-lockfile"},
        severity_overrides={"react.unsafe-target-blank": __import__("njordscan.core.severity", fromlist=["Severity"]).Severity.CRITICAL},
    )
    assert not any(f.rule_id == "supply-chain.missing-lockfile" for f in tuned.findings)
    tb = [f for f in tuned.findings if f.rule_id == "react.unsafe-target-blank"]
    if tb:
        assert tb[0].effective_severity.value == "critical"


# --- autofix ---

async def test_autofix_is_additive_and_safe(tmp_path):
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work)
    result = await scan(work)
    report = apply_fixes(result, result.project, dry_run=False)

    assert report.count >= 1
    share = (work / "components" / "Share.jsx").read_text()
    assert 'rel="noopener noreferrer"' in share
    # a link that already had rel must be untouched (exactly one rel on that line)
    safe = (work / "components" / "SafeLink.jsx").read_text()
    assert safe.count("noopener") == 1

    rescan = await scan(work, only_detectors=["patterns"])
    assert not any(f.rule_id == "react.unsafe-target-blank" for f in rescan.findings)


async def test_autofix_dry_run_changes_nothing(tmp_path):
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work)
    before = (work / "components" / "Share.jsx").read_text()
    result = await scan(work)
    report = apply_fixes(result, result.project, dry_run=True)
    assert report.dry_run
    assert (work / "components" / "Share.jsx").read_text() == before  # unchanged


# --- html report ---

async def test_html_report_escapes_and_renders(tmp_path):
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work)
    (work / "pages" / "x.jsx").write_text(
        'export default () => { el.innerHTML = req.query.q; /* <script>alert(1)</script> */ };'
    )
    result = await scan(work)
    html = render_html(result)
    assert "<!doctype html>" in html
    assert "<script>alert(1)</script>" not in html   # raw script must be escaped
    assert "Why this matters" in html

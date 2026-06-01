"""Detector behavior against the fixture apps.

These tests encode the V1 false-negatives we set out to fix: env-file secrets,
dangerouslySetInnerHTML, cross-function taint, and known-vulnerable dependencies.
They also assert the clean app stays quiet (no false positives).
"""

from __future__ import annotations

import pytest

from conftest import rule_ids, scan

pytestmark = pytest.mark.asyncio


async def test_secrets_detects_env_file_credentials(vuln_app):
    result = await scan(vuln_app, only_detectors=["secrets"])
    ids = rule_ids(result.findings)
    # V1 missed all of these in a .env file.
    assert "secret.aws-access-key" in ids
    assert "secret.generic" in ids            # db url / stripe / github token
    assert "secret.public-env-exposure" in ids
    files = {f.file for f in result.findings}
    assert any(".env" in f for f in files)


async def test_secrets_detects_stripe_key(tmp_path):
    """Provider-key coverage. The key is built at runtime so no `sk_live_` literal
    is ever committed (which would trip GitHub push protection / secret scanners)."""
    stripe = "sk_" + "live_" + "51Mh3kLZx9QpWvNbR7tYcUiOaPq"  # synthetic, not a real key
    (tmp_path / "package.json").write_text('{"name":"t"}')
    (tmp_path / ".env").write_text(f"STRIPE_SECRET_KEY={stripe}\n")
    result = await scan(tmp_path, only_detectors=["secrets"])
    assert any("Stripe" in f.message for f in result.findings)


async def test_supply_chain_flags_dangerous_postinstall_and_lockfile(vuln_app):
    result = await scan(vuln_app, only_detectors=["supply-chain"])
    ids = rule_ids(result.findings)
    assert "supply-chain.dangerous-install-script" in ids
    assert "supply-chain.missing-lockfile" in ids


async def test_static_analysis_catches_dangerously_set_inner_html(vuln_app):
    result = await scan(vuln_app, only_detectors=["static"])
    ids = rule_ids(result.findings)
    assert "xss.dangerously-set-inner-html" in ids   # the #1 React XSS sink V1 missed
    assert "injection.eval" in ids
    assert "xss.inner-html" in ids


async def test_taint_tracks_cross_function_flow(vuln_app):
    """The headline feature: req.body -> renderInto(value) -> innerHTML."""
    result = await scan(vuln_app, only_detectors=["taint"])
    xss = [f for f in result.findings if f.rule_id == "xss.inner-html" and "render.js" in f.file]
    assert xss, "cross-function taint flow not detected"
    # the finding should carry a source->sink flow
    assert any(f.taint_flow for f in xss)


async def test_dependencies_flags_known_vulnerable_versions(vuln_app):
    result = await scan(vuln_app, only_detectors=["dependencies"])
    msgs = " ".join(f.message.lower() for f in result.findings)
    assert "lodash" in msgs       # lodash 4.17.4 has multiple real CVEs
    assert "next" in msgs         # next 12.0.0
    assert all(f.rule_id == "deps.known-vulnerability" for f in result.findings) or any(
        f.rule_id == "deps.known-vulnerability" for f in result.findings
    )


async def test_configs_flags_dangerous_next_config(vuln_app):
    result = await scan(vuln_app, only_detectors=["configs"])
    ids = rule_ids(result.findings)
    assert "nextjs.dangerous-config" in ids


async def test_clean_app_has_no_findings(clean_app):
    """A well-built app must not produce false positives — trust depends on it."""
    result = await scan(clean_app)
    assert result.total == 0, [f"{f.rule_id}@{f.location}" for f in result.findings]


async def test_no_detector_crashes_on_full_scan(vuln_app):
    result = await scan(vuln_app)
    assert result.errors == []
    assert result.total > 10

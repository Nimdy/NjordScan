"""CLI behavior: exit codes (the V1 regressions) and core commands."""

from __future__ import annotations

from click.testing import CliRunner

from njordscan.cli import cli

from conftest import CLEAN_APP, VULN_APP

runner = CliRunner()


def test_version_flag_exits_zero():
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "njordscan" in result.output.lower()


def test_scan_without_fail_on_exits_zero_even_with_findings():
    result = runner.invoke(cli, ["scan", str(VULN_APP), "--quiet"])
    assert result.exit_code == 0


def test_fail_on_gates_without_ci_flag():
    """V1 bug: --fail-on was ignored unless --ci was also passed."""
    result = runner.invoke(cli, ["scan", str(VULN_APP), "--quiet", "--fail-on", "high"])
    assert result.exit_code == 1


def test_brief_hides_explanations():
    full = runner.invoke(cli, ["scan", str(VULN_APP), "--only", "secrets"])
    brief = runner.invoke(cli, ["scan", str(VULN_APP), "--only", "secrets", "--brief"])
    assert "Why this matters" in full.output
    assert "Why this matters" not in brief.output  # terse output drops the detail
    assert brief.exit_code == 0


def test_no_external_blocks_remote_ai():
    r = runner.invoke(cli, ["scan", str(VULN_APP), "--only", "secrets", "--quiet",
                            "--explain-with-ai", "--ai-provider", "openai", "--no-external"])
    assert r.exit_code == 0  # never crashes
    assert "no-external" in r.output.lower() or "skipping remote" in r.output.lower()


def test_mode_quick_runs_fewer_detectors():
    quick = runner.invoke(cli, ["scan", str(VULN_APP), "--mode", "quick", "--format", "json"])
    std = runner.invoke(cli, ["scan", str(VULN_APP), "--mode", "standard", "--format", "json"])
    import json as _json
    q = {f["detector"] for f in _json.loads(quick.output)["findings"]}
    s = {f["detector"] for f in _json.loads(std.output)["findings"]}
    assert "taint" not in q and "dependencies" not in q
    assert "taint" in s or "dependencies" in s


def test_fail_on_clean_app_exits_zero():
    result = runner.invoke(cli, ["scan", str(CLEAN_APP), "--quiet", "--fail-on", "critical"])
    assert result.exit_code == 0


def test_bad_path_exits_with_error_code():
    result = runner.invoke(cli, ["scan", "/nonexistent/path/xyz", "--quiet"])
    assert result.exit_code == 2


def test_explain_lists_rules():
    result = runner.invoke(cli, ["explain"])
    assert result.exit_code == 0
    assert "xss" in result.output


def test_explain_unknown_rule_errors():
    result = runner.invoke(cli, ["explain", "no.such.rule"])
    assert result.exit_code == 2

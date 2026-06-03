"""AI excessive-agency detector — model-controlled value reaching a dangerous sink.

The vulnerable fixtures each wire a tool/LLM-output into a genuinely dangerous sink
(exec / eval / fs-write / raw SQL / SSRF) and MUST fire; the safe fixtures keep the
model away from any dangerous sink (returns data, ORM, fixed host/command) and MUST
stay silent. This is the precision property that made this feature shippable where
authz-consistency was not: the sink is dangerous regardless of context.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import FIXTURES, rule_ids, scan

pytestmark = pytest.mark.asyncio

CASES = FIXTURES / "rule-cases" / "ai-agency"


async def _ids(path: Path) -> set[str]:
    result = await scan(path, only_detectors=["ai_agency"])
    return rule_ids(result.findings)


async def test_vulnerable_tools_and_output_are_flagged():
    ids = await _ids(CASES / "vulnerable")
    assert "ai.excessive-agency-command" in ids      # exec-tool + interproc-tool (one hop)
    assert "ai.excessive-agency-code" in ids         # eval-tool
    assert "ai.excessive-agency-filesystem" in ids   # fs-tool
    assert "ai.excessive-agency-sql" in ids          # sql-tool
    assert "ai.tool-ssrf" in ids                     # ssrf-tool
    assert "ai.improper-output-handling" in ids      # llm-eval


async def test_safe_tools_stay_silent():
    result = await scan(CASES / "safe", only_detectors=["ai_agency"])
    # weather (returns data), db-read (ORM), fetch-fixed (fixed host), exec-fixed
    # (no model input), llm-render (output returned as data) — none reach a dangerous sink.
    agency_ids = {i for i in rule_ids(result.findings) if i.startswith("ai.excessive-agency") or i in ("ai.tool-ssrf", "ai.improper-output-handling")}
    assert agency_ids == set(), f"false positives on safe AI tools: {agency_ids}"


async def test_interprocedural_recall():
    """A dangerous op one hop away in a helper the tool calls is still caught."""
    result = await scan(CASES / "vulnerable", only_detectors=["ai_agency"])
    hit = [f for f in result.findings
           if "interproc-tool" in f.file and f.rule_id == "ai.excessive-agency-command"]
    assert hit, "interprocedural (helper-hidden) sink was missed"


async def test_clean_app_has_no_agency_findings(clean_app):
    """A normal app with no AI tools must produce zero agency findings."""
    result = await scan(clean_app, only_detectors=["ai_agency"])
    assert rule_ids(result.findings) == set()

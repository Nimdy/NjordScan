"""A single hung detector must not take the whole scan down.

The orchestrator already isolates a detector that *raises*; this pins that it also
contains one that *hangs* (a stuck live probe, a ReDoS pattern on a pathological
line). A scan that blocks forever is worse than one that crashes — in CI it stalls
the runner with no output. The per-detector timeout reports the hang as an isolated
error and lets the rest of the scan finish.
"""

from __future__ import annotations

import asyncio

import pytest

from njordscan.core import orchestrator as orch_mod
from njordscan.core.config import Config
from njordscan.core.orchestrator import Orchestrator

pytestmark = pytest.mark.asyncio


class _HangingDetector:
    id = "hanger"

    def applies(self, project) -> bool:
        return True

    async def scan(self, project):
        await asyncio.sleep(30)  # would block the entire scan
        return []


class _FastDetector:
    id = "fast"

    def applies(self, project) -> bool:
        return True

    async def scan(self, project):
        return []


async def test_hanging_detector_is_contained_as_an_error(tmp_path, monkeypatch):
    (tmp_path / "a.js").write_text("const x = 1;\n")
    monkeypatch.setattr(
        orch_mod, "load_detectors", lambda: [_HangingDetector(), _FastDetector()]
    )

    result = await Orchestrator(
        Config(target=tmp_path, detector_timeout=0.5, reachability=False)
    ).run()

    # the scan COMPLETED (it didn't hang) and reported the timeout, isolated to one detector
    assert any("hanger" in e and "timed out" in e for e in result.errors), result.errors
    # the other detector still ran to completion
    assert result.findings == []


async def test_timeout_disabled_runs_normally(tmp_path, monkeypatch):
    (tmp_path / "a.js").write_text("const x = 1;\n")
    monkeypatch.setattr(orch_mod, "load_detectors", lambda: [_FastDetector()])

    result = await Orchestrator(
        Config(target=tmp_path, detector_timeout=0, reachability=False)
    ).run()

    assert result.errors == []

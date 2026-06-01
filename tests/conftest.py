"""Shared test fixtures."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import List

# Isolate tests from the developer's machine: point NJORDSCAN_HOME at an empty
# dir so the dependencies detector uses only the SHIPPED advisory seed, never the
# user's `njordscan update` cache (which changes over time and would make tests
# non-deterministic). Set before any njordscan import triggers advisory loading.
os.environ["NJORDSCAN_HOME"] = os.path.join(tempfile.gettempdir(), "njordscan-test-home-empty")

import pytest

from njordscan.core.config import Config
from njordscan.core.finding import Finding
from njordscan.core.orchestrator import Orchestrator, ScanResult

FIXTURES = Path(__file__).parent / "fixtures"
VULN_APP = FIXTURES / "vulnerable-app"
CLEAN_APP = FIXTURES / "clean-app"


@pytest.fixture
def vuln_app() -> Path:
    return VULN_APP


@pytest.fixture
def clean_app() -> Path:
    return CLEAN_APP


async def scan(path: Path, **cfg) -> ScanResult:
    """Run a full scan and return the result."""
    config = Config(target=path, **cfg)
    return await Orchestrator(config).run()


def rule_ids(findings: List[Finding]) -> set[str]:
    return {f.rule_id for f in findings}

"""Integrity guards for the data-driven rule library.

These catch the classic ways a large YAML rule set rots: a pattern with no
knowledge entry, a bad regex, or a rule that starts firing on clean code.
"""

from __future__ import annotations

import glob
from pathlib import Path

import pytest
import yaml

from njordscan.detectors.pattern_engine import _load_patterns
from njordscan.knowledge import all_rules, registry

from conftest import scan

PKG = Path(__file__).resolve().parent.parent / "njordscan"


def test_all_patterns_compile():
    patterns = _load_patterns()
    assert len(patterns) > 50, "expected a substantial pattern library"


def test_no_orphan_patterns():
    """Every pattern's rule_id must have a knowledge entry, or findings can't be explained."""
    reg = registry()
    orphans = []
    for pf in glob.glob(str(PKG / "data" / "patterns" / "*.yaml")):
        for entry in yaml.safe_load(Path(pf).read_text()) or []:
            rid = entry.get("rule_id")
            if rid not in reg:
                orphans.append((Path(pf).name, rid))
    assert not orphans, f"patterns without knowledge entries: {orphans}"


def test_every_rule_is_educational():
    """The core promise: every rule explains why it matters and how to fix it."""
    for rule in all_rules():
        assert rule.why.strip(), f"{rule.id} missing why"
        assert rule.fix.strip(), f"{rule.id} missing fix"


def test_rule_ids_unique_across_yaml():
    seen = set()
    dupes = []
    for rf in glob.glob(str(PKG / "data" / "rules" / "*.yaml")):
        for entry in yaml.safe_load(Path(rf).read_text()) or []:
            rid = entry.get("id")
            if rid in seen:
                dupes.append(rid)
            seen.add(rid)
    assert not dupes, f"duplicate rule ids in YAML: {dupes}"


@pytest.mark.asyncio
async def test_patterns_quiet_on_clean_app(clean_app):
    """The whole pattern library must produce zero findings on a clean app."""
    result = await scan(clean_app, only_detectors=["patterns"])
    assert result.total == 0, [f"{f.rule_id}@{f.location}" for f in result.findings]


@pytest.mark.asyncio
async def test_library_has_broad_coverage(clean_app):
    """Sanity: we ship rules across many namespaces (react, nextjs, vite, crypto, ...)."""
    namespaces = {r.id.split(".")[0] for r in all_rules()}
    for ns in ("react", "nextjs", "vite", "crypto", "injection", "auth", "cors"):
        assert ns in namespaces, f"missing rule namespace: {ns}"

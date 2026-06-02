"""Reachability analysis — import-graph reachability from framework entrypoints."""

from __future__ import annotations

import pytest

from njordscan.core.config import Config
from njordscan.core.project import Project
from njordscan.core.reachability import ReachabilityGraph

from conftest import FIXTURES, scan

REACHABLE_APP = FIXTURES / "reachable-app"
# asyncio_mode=auto runs the async tests; this file also has one sync test, so no module mark.


def _for(findings, rel):
    return [f for f in findings if f.file == rel]


async def test_reachable_vs_unreachable_code():
    result = await scan(REACHABLE_APP)
    db = _for(result.findings, "lib/db.ts")            # imported by the API route
    orphan = _for(result.findings, "lib/orphan.ts")    # imported by nothing
    widget = _for(result.findings, "components/Widget.tsx")   # imported by the page
    unused = _for(result.findings, "components/Unused.tsx")   # imported by nothing

    assert db and all(f.reachable for f in db)
    assert orphan and all(f.reachable is False for f in orphan)
    assert widget and all(f.reachable for f in widget)
    assert unused and all(f.reachable is False for f in unused)
    # the route-reached helper runs server-side
    assert db[0].metadata["reachability"]["kind"] == "server"
    assert widget[0].metadata["reachability"]["kind"] == "client"


def test_graph_entrypoints_and_lookup():
    proj = Project.load(Config(target=REACHABLE_APP))
    g = ReachabilityGraph(proj)
    assert g.entrypoint_count >= 2           # the route + the page
    assert g.lookup("lib/db.ts").reachable
    assert g.lookup("lib/db.ts").kind == "server"
    assert not g.lookup("lib/orphan.ts").reachable
    assert "app/api/search/route.ts" in g.lookup("lib/db.ts").path


async def test_reachable_only_drops_dead_code():
    full = await scan(REACHABLE_APP, only_detectors=["static", "patterns"])
    only = await scan(REACHABLE_APP, only_detectors=["static", "patterns"], reachable_only=True)
    assert only.total < full.total
    assert all(f.reachable is not False for f in only.findings)


async def test_no_entrypoints_is_inconclusive(tmp_path):
    """If we can't find entrypoints, don't claim everything is unreachable."""
    (tmp_path / "package.json").write_text('{"name":"x"}')
    (tmp_path / "helper.js").write_text("el.innerHTML = req.body.x;\n")
    result = await scan(tmp_path)
    assert any(f.reachable is None for f in result.findings)

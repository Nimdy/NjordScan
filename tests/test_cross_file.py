"""Cross-file interprocedural taint — user input through an imported helper to a sink."""

from __future__ import annotations

import pytest

from njordscan.detectors.taint import _named_imports, _resolve_import

from conftest import FIXTURES, scan

CROSS = FIXTURES / "cross-file-app"
# asyncio_mode=auto runs the async tests; this file mixes sync + async, so no module mark.


@pytest.mark.asyncio
async def test_taint_flows_through_imported_helper():
    result = await scan(CROSS, only_detectors=["taint"])
    xss = [f for f in result.findings if f.rule_id == "xss.inner-html"]
    assert len(xss) == 1
    f = xss[0]
    assert f.file == "app/api/save/route.ts"   # reported at the call site
    labels = " ".join(s.label for s in f.taint_flow)
    assert "req.body" in labels                 # the source
    assert "lib/render.ts" in labels            # the cross-file sink location is named
    assert f.confidence == "high"


@pytest.mark.asyncio
async def test_safe_cross_file_calls_not_flagged():
    """safeText() (textContent, not a sink) and a constant argument must not fire."""
    result = await scan(CROSS, only_detectors=["taint"])
    assert len(result.findings) == 1


def test_named_import_parsing():
    out = _named_imports("import { a, b as c, type T } from './m';\nimport x from './d';")
    assert out == {"a": ("./m", "a"), "c": ("./m", "b")}   # default/namespace/type ignored


def test_relative_import_resolution():
    files = {"lib/render.ts", "app/api/save/route.ts", "lib/index.js"}
    assert _resolve_import("app/api/save/route.ts", "../../../lib/render", files) == "lib/render.ts"
    assert _resolve_import("app/api/save/route.ts", "../../../lib", files) == "lib/index.js"
    assert _resolve_import("a/b.ts", "./nope", files) is None

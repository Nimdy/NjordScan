"""Dev-only files (scripts/, build tooling, tests) are de-prioritized, not hidden.

Found by dogfooding a real app: a command-exec and a logged token in a local
``scripts/get-gmail-token.ts`` showed as Critical/High next to real route-handler
findings. Those files aren't the deployed app surface, so findings there are capped to
LOW and annotated with the reason — while the SAME pattern in app code keeps full
severity and is never hidden.
"""

from __future__ import annotations

import pytest

from conftest import scan
from njordscan.core.severity import Severity

pytestmark = pytest.mark.asyncio

# high-entropy, NOT a provider key format (so it can't trip secret push-protection)
_SECRET = "kJ8x" + "Qz2Lp9" + "Wm4Rt7" + "Vn3Bd6q"


async def test_dev_only_findings_are_capped_and_annotated(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "config.ts").write_text(f'export const apiSecret = "{_SECRET}";\n')
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "seed.ts").write_text(f'const apiSecret = "{_SECRET}";\n')
    (tmp_path / "package.json").write_text('{"name":"a","dependencies":{"next":"14.0.0"}}')

    r = await scan(tmp_path)
    app = [f for f in r.findings if f.file.startswith("app/")]
    scr = [f for f in r.findings if f.file.startswith("scripts/")]

    assert app, "the app-code secret must still be reported at full severity"
    assert scr, "the script secret is de-prioritized, NOT hidden"
    # app keeps its real (>LOW) severity; the script copy is capped to LOW + told why
    assert any(f.effective_severity.rank > Severity.LOW.rank for f in app)
    assert all(f.effective_severity == Severity.LOW for f in scr)
    assert all(f.metadata.get("deprioritized") for f in scr)
    assert all(f.metadata.get("original_severity") for f in scr)


async def test_in_app_tools_route_is_not_treated_as_tooling(tmp_path):
    """A deployed `app/tools/...` route must NOT be mistaken for top-level tooling."""
    (tmp_path / "app" / "tools").mkdir(parents=True)
    (tmp_path / "app" / "tools" / "page.tsx").write_text(f'const apiSecret = "{_SECRET}";\n')
    (tmp_path / "package.json").write_text('{"name":"a","dependencies":{"next":"14.0.0"}}')

    r = await scan(tmp_path)
    tools = [f for f in r.findings if f.file.startswith("app/tools/")]
    assert tools, "in-app route finding must be reported"
    assert all(not f.metadata.get("deprioritized") for f in tools)
    assert any(f.effective_severity.rank > Severity.LOW.rank for f in tools)

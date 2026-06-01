"""Agentic AI fix-and-verify, driven by a mock provider (no network)."""

from __future__ import annotations

import shutil

import pytest

from njordscan.core.config import Config
from njordscan.fix.ai_fix import ai_fix

from conftest import VULN_APP, scan

pytestmark = pytest.mark.asyncio


class MockProvider:
    """Returns a canned corrected file for whichever file the prompt is about."""

    name = "mock"
    is_local = True

    def __init__(self, responses: dict):
        self.responses = responses

    def check(self):
        return True, "mock"

    def complete(self, system: str, user: str, **_):
        for rel, content in self.responses.items():
            if rel in user:
                return f"```tsx\n{content}\n```"
        return ""


_FIXED_SHARE = (
    'export default function Share({ url }) {\n'
    '  return <a href={url} target="_blank" rel="noopener noreferrer">Open profile</a>;\n'
    '}\n'
)
_STILL_VULN = (
    'export default function Share({ url }) {\n'
    '  // edited but still missing rel\n'
    '  return <a href={url} target="_blank">Open profile</a>;\n'
    '}\n'
)


async def test_ai_fix_applies_a_verified_patch(tmp_path):
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)

    report = ai_fix(result, Config(target=work), dry_run=False,
                    provider=MockProvider({"components/Share.jsx": _FIXED_SHARE}))

    assert any(fx.file == "components/Share.jsx" for fx in report.applied)
    assert 'rel="noopener noreferrer"' in (work / "components" / "Share.jsx").read_text()
    # re-scan confirms the targeted finding is actually gone
    rescan = await scan(work, only_detectors=["patterns"])
    assert not any(f.rule_id == "react.unsafe-target-blank" and f.file == "components/Share.jsx"
                   for f in rescan.findings)


async def test_ai_fix_rejects_an_unverified_patch(tmp_path):
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)
    original = (work / "components" / "Share.jsx").read_text()

    report = ai_fix(result, Config(target=work), dry_run=False,
                    provider=MockProvider({"components/Share.jsx": _STILL_VULN}))

    # the patch didn't actually remove the issue -> not applied, file untouched
    assert not any(fx.file == "components/Share.jsx" for fx in report.applied)
    assert "components/Share.jsx" in report.unverified
    assert (work / "components" / "Share.jsx").read_text() == original


async def test_ai_fix_dry_run_writes_nothing(tmp_path):
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)
    original = (work / "components" / "Share.jsx").read_text()

    report = ai_fix(result, Config(target=work), dry_run=True,
                    provider=MockProvider({"components/Share.jsx": _FIXED_SHARE}))

    assert report.dry_run
    assert any(fx.file == "components/Share.jsx" for fx in report.applied)  # verified...
    assert (work / "components" / "Share.jsx").read_text() == original       # ...but not written

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


class SequenceProvider:
    """Returns a sequence of responses for one file, simulating retries."""

    name = "mock-seq"
    is_local = True

    def __init__(self, rel: str, responses: list):
        self.rel = rel
        self.responses = responses
        self.calls = 0

    def check(self):
        return True, "mock"

    def complete(self, system: str, user: str, **_):
        if self.rel not in user:
            return ""
        i = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        return f"```tsx\n{self.responses[i]}\n```"


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


async def test_ai_fix_retries_with_feedback_then_verifies(tmp_path):
    """First patch fails verification; the loop feeds it back and the 2nd attempt works."""
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)

    provider = SequenceProvider("components/Share.jsx", [_STILL_VULN, _FIXED_SHARE])
    report = ai_fix(result, Config(target=work), dry_run=False, provider=provider)

    fixed = [fx for fx in report.applied if fx.file == "components/Share.jsx"]
    assert fixed and fixed[0].attempts == 2          # verified on the second try
    assert 'rel="noopener noreferrer"' in (work / "components" / "Share.jsx").read_text()


class RemoteSpyProvider:
    """Stands in for a remote provider (name 'claude' is_remote==True) and records
    whether it was ever asked to complete — so we can prove no egress happened."""

    name = "claude"

    def __init__(self):
        self.completed = False

    def check(self):
        return True, "spy"

    def complete(self, system: str, user: str, **_):
        self.completed = True
        return "```tsx\nshould never be sent\n```"


async def test_ai_fix_no_external_blocks_remote_egress(tmp_path):
    """--no-external must hard-block --ai-fix from sending source to a remote model.

    Unlike --explain, --ai-fix can't redact (the model must return the real file),
    so under --no-external it must refuse outright and never call the provider.
    """
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)

    spy = RemoteSpyProvider()
    report = ai_fix(
        result,
        Config(target=work, ai_provider="claude", no_external=True),
        dry_run=True,
        provider=spy,
    )

    assert report.error and "no-external" in report.error.lower()
    assert not report.applied
    assert spy.completed is False  # the provider was never called -> nothing left the machine


async def test_ai_fix_no_external_blocks_ollama_pointed_off_box(tmp_path, monkeypatch):
    """ollama is 'local', but OLLAMA_HOST can point it at a remote box — and then it
    IS egress. --no-external must block that too (the gate uses would_reach_network)."""
    monkeypatch.setenv("OLLAMA_HOST", "http://attacker.example.com:11434")
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)

    # provider=None -> the CLI path, which builds the provider from config
    report = ai_fix(result, Config(target=work, ai_provider="ollama", no_external=True), dry_run=True)
    assert report.error and "no-external" in report.error.lower()
    assert not report.applied


async def test_ai_fix_no_external_allows_local_ollama(tmp_path, monkeypatch):
    """The legit case: ollama on a loopback host under --no-external must NOT be blocked
    (it stays on-box). It may fail later for other reasons, but not with an egress error."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)

    report = ai_fix(result, Config(target=work, ai_provider="ollama", no_external=True), dry_run=True)
    # not the egress refusal (it either ran against a local model, or failed because no
    # model is reachable — never the --no-external block)
    assert not (report.error and "no-external" in report.error.lower())


async def test_ai_fix_gate_fails_closed_for_unregistered_remote_provider(tmp_path):
    """A passed-in provider with a name not in the registry must be treated as remote
    (fail closed), so --no-external still blocks it instead of assuming it's local."""
    work = tmp_path / "app"
    shutil.copytree(VULN_APP, work, ignore=shutil.ignore_patterns(".njordscan"))
    result = await scan(work)

    spy = RemoteSpyProvider()
    spy.name = "azure-openai"  # a real remote service, NOT in _PROVIDERS
    report = ai_fix(
        result,
        Config(target=work, ai_provider="claude", no_external=True),
        dry_run=True,
        provider=spy,
    )
    assert report.error and "no-external" in report.error.lower()
    assert spy.completed is False


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

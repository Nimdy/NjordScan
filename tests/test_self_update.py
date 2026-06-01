"""Self-updating threat intel: rules/patterns feed + staleness awareness.

These cover the 'self-updating' half — fetching a JSON manifest of fresh detection
rules + patterns into ~/.njordscan and merging them on top of the shipped data,
without a reinstall. Network is faked; nothing here hits the internet.
"""

from __future__ import annotations

import json

import pytest

from njordscan import update
from njordscan.knowledge import get_rule, registry


class _FakeResp:
    def __init__(self, payload: dict) -> None:
        self._b = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._b

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *a) -> bool:
        return False


def _serve(monkeypatch, manifest: dict) -> None:
    monkeypatch.setattr(update.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(manifest))


# --- filename safety (a security tool must not let a feed write outside its cache) ---

@pytest.mark.parametrize("name,ok", [
    ("rules.yaml", True),
    ("more.yml", True),
    ("../../etc/passwd", False),
    ("../escape.yaml", False),
    ("nested/dir.yaml", False),
    (".hidden.yaml", False),
    ("notyaml.txt", False),
    ("", False),
])
def test_safe_yaml_name(name, ok):
    result = update._safe_yaml_name(name)
    assert (result is not None) == ok
    if ok:
        assert "/" not in result and not result.startswith("..")


def test_write_feed_files_skips_unsafe_and_malformed(tmp_path):
    n = update._write_feed_files(tmp_path, {
        "good.yaml": "- id: x\n  title: t\n  severity: low\n  why: w\n  fix: f\n",
        "../evil.yaml": "- id: y\n",               # path traversal → skipped
        "bad.yaml": "::: not : valid : yaml :::",   # unparseable → skipped
        "notyaml.txt": "ignored",                   # wrong extension → skipped
    })
    assert n == 1
    assert (tmp_path / "good.yaml").exists()
    assert not (tmp_path / "evil.yaml").exists()
    assert not (tmp_path.parent / "evil.yaml").exists()


# --- the round trip: fetch a feed, see the new rule + pattern take effect ---

def test_fetch_rules_feed_merges_new_rule(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path))
    manifest = {
        "version": "2026.06.01",
        "rules": {"feed-rules.yaml":
                  "- id: feed.injected-rule\n"
                  "  title: A rule delivered by the feed\n"
                  "  severity: high\n"
                  "  why: It came from the self-updating feed.\n"
                  "  fix: Nothing — this is a test.\n"},
        "patterns": {"feed-patterns.yaml":
                     "- rule_id: feed.injected-rule\n"
                     "  pattern: 'TOTALLY_UNIQUE_FEED_TOKEN'\n"},
    }
    _serve(monkeypatch, manifest)
    try:
        result = update.fetch_rules_feed("https://example.test/feed.json")
        assert result["rules_written"] == 1 and result["patterns_written"] == 1
        assert result["version"] == "2026.06.01"

        registry.cache_clear()
        rule = get_rule("feed.injected-rule")
        assert rule is not None and rule.severity.value == "high"

        from njordscan.detectors.pattern_engine import _load_patterns
        ids = {p.rule_id for p in _load_patterns()}
        assert "feed.injected-rule" in ids
    finally:
        registry.cache_clear()


def test_fetch_rules_feed_rejects_non_object(monkeypatch):
    _serve(monkeypatch, ["not", "an", "object"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        update.fetch_rules_feed("https://example.test/feed.json")


# --- staleness awareness ---

def test_staleness_hint_when_never_fetched(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path))   # empty → nothing fetched
    assert update.data_age_days() is None
    hint = update.staleness_hint()
    assert hint and "njordscan update" in hint


def test_staleness_hint_quiet_when_fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("NJORDSCAN_HOME", str(tmp_path))
    update.user_advisories_path().parent.mkdir(parents=True, exist_ok=True)
    update.user_advisories_path().write_text("{}")        # just-written → fresh
    age = update.data_age_days()
    assert age is not None and age < 1
    assert update.staleness_hint() is None

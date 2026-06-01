"""Core model tests: severity, finding, enrichment."""

from __future__ import annotations

from njordscan.core.finding import Finding
from njordscan.core.severity import Severity
from njordscan.knowledge import all_rules, enrich, get_rule


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.HIGH.meets(Severity.MEDIUM)
    assert not Severity.LOW.meets(Severity.HIGH)


def test_severity_from_str_and_sarif():
    assert Severity.from_str("CRITICAL") is Severity.CRITICAL
    assert Severity.CRITICAL.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"


def test_finding_fingerprint_is_stable_and_ignores_message():
    a = Finding(rule_id="xss.inner-html", file="a.js", line=3, code_snippet="el.innerHTML = x", message="m1")
    b = Finding(rule_id="xss.inner-html", file="a.js", line=3, code_snippet="el.innerHTML = x", message="m2")
    assert a.fingerprint == b.fingerprint  # message must not affect identity
    c = Finding(rule_id="xss.inner-html", file="a.js", line=4, code_snippet="el.innerHTML = x")
    assert a.fingerprint != c.fingerprint


def test_enrich_populates_education_from_rule():
    f = enrich(Finding(rule_id="xss.dangerously-set-inner-html", file="C.jsx", line=2))
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-79"
    assert "dangerouslySetInnerHTML" in f.title
    assert f.why and f.fix  # the educational payload is present
    assert f.references


def test_enrich_preserves_detector_overrides():
    f = Finding(rule_id="xss.inner-html", file="a.js", line=1, severity=Severity.CRITICAL, message="custom")
    enrich(f)
    assert f.severity is Severity.CRITICAL  # override kept
    assert f.message == "custom"


def test_enrich_unknown_rule_defaults_safely():
    f = enrich(Finding(rule_id="not.a.real.rule", file="a.js", line=1))
    assert f.severity is Severity.MEDIUM
    assert f.title == "not.a.real.rule"


def test_every_rule_has_education():
    for rule in all_rules():
        assert rule.why.strip(), f"{rule.id} missing 'why'"
        assert rule.fix.strip(), f"{rule.id} missing 'fix'"
        assert rule.severity in Severity
        assert get_rule(rule.id) is rule

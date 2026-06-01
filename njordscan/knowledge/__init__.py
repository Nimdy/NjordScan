"""Knowledge base: turns a bare ``rule_id`` into a teachable, fixable finding."""

from __future__ import annotations

from functools import lru_cache
from typing import Dict, List

from ..core.finding import Finding
from ..core.severity import Severity
from .loader import load_yaml_rules
from .rules import RULES as _CORE_RULES
from .rules import Rule

__all__ = ["enrich", "get_rule", "all_rules", "Rule", "registry"]


@lru_cache(maxsize=1)
def registry() -> Dict[str, Rule]:
    """All rules, core + YAML-loaded. Core rules win on id collision."""
    merged: Dict[str, Rule] = {}
    merged.update(load_yaml_rules())   # data/rules/*.yaml
    merged.update(_CORE_RULES)         # built-in core takes precedence
    return merged


def get_rule(rule_id: str):
    return registry().get(rule_id)


def all_rules() -> List[Rule]:
    return list(registry().values())


def enrich(finding: Finding) -> Finding:
    """Populate a finding's educational fields from its rule, unless already set.

    Detectors emit findings with just ``rule_id`` + location. This fills in the
    title, severity, standards mappings, and the why/fix/secure_example prose so
    every finding a user sees explains itself. Per-occurrence overrides set by a
    detector (e.g. a bumped severity, a custom message) are preserved.
    """
    rule = registry().get(finding.rule_id)
    if rule is None:
        # Unknown rule: leave detector-provided values, just ensure title/severity exist.
        if not finding.title:
            finding.title = finding.rule_id
        if finding.severity is None:
            finding.severity = Severity.MEDIUM
        return finding

    if not finding.title:
        finding.title = rule.title
    # Detectors default severity to INFO; if they didn't deliberately set one,
    # use the rule's canonical severity.
    if finding.severity is None:
        finding.severity = rule.severity
    if not finding.why:
        finding.why = rule.why
    if not finding.fix:
        finding.fix = rule.fix
    if not finding.secure_example:
        finding.secure_example = rule.secure_example
    if finding.cwe is None:
        finding.cwe = rule.cwe
    if finding.owasp is None:
        finding.owasp = rule.owasp
    if not finding.references:
        finding.references = list(rule.references)
    if not finding.attack:
        from .attack import techniques_for
        finding.attack = techniques_for(finding.rule_id)
    return finding

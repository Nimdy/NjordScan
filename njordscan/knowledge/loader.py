"""Load knowledge-base rules from YAML so the library can grow as data.

Core rules live in :mod:`njordscan.knowledge.rules` (rich Python literals).
Additional rules — especially the large, category-organized library — live in
``njordscan/data/rules/*.yaml`` and are loaded here and merged in.

YAML schema (one list item per rule), mirroring :class:`~njordscan.knowledge.rules.Rule`:

    - id: react.unsafe-target-blank
      title: 'Link opens with target="_blank" but no rel="noopener"'
      severity: low                  # critical|high|medium|low|info
      cwe: CWE-1022
      owasp: "A01:2021-Broken Access Control"
      why: |
        Plain-English explanation of why this matters...
      fix: |
        Plain-English fix...
      secure_example: |
        <a href={url} target="_blank" rel="noopener noreferrer">Open</a>
      references:
        - https://owasp.org/...
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict

import yaml

from ..core.severity import Severity
from .rules import Rule

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).resolve().parent.parent / "data" / "rules"


def _to_rule(entry: dict, source: str) -> Rule | None:
    try:
        rid = entry["id"]
        title = entry["title"]
        severity = Severity.from_str(str(entry["severity"]))
        why = entry["why"]
        fix = entry["fix"]
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("invalid rule in %s (%s): %r", source, exc, entry)
        return None
    refs = entry.get("references") or []
    if isinstance(refs, str):
        refs = [refs]
    return Rule(
        id=str(rid),
        title=str(title),
        severity=severity,
        why=str(why).strip(),
        fix=str(fix).strip(),
        secure_example=str(entry.get("secure_example", "")).strip(),
        cwe=entry.get("cwe"),
        owasp=entry.get("owasp"),
        references=[str(r) for r in refs],
    )


def load_yaml_rules(directory: Path | None = None) -> Dict[str, Rule]:
    directory = directory or _RULES_DIR
    out: Dict[str, Rule] = {}
    if not directory.exists():
        return out
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("could not load rules file %s: %s", path, exc)
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            rule = _to_rule(entry, path.name)
            if rule:
                out[rule.id] = rule
    return out

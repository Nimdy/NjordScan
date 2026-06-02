"""MITRE ATT&CK mapping.

Maps each NjordScan rule to one or more MITRE ATT&CK technique ids, so findings
speak the language security teams use for threat modeling and coverage — and so
we can export an ATT&CK Navigator layer of an app's attack surface.

Data lives in ``njordscan/data/attack_map.yaml``:

    techniques:                 # the catalog (id -> name, tactic)
      T1059.007: { name: "Command and Scripting Interpreter: JavaScript", tactic: "Execution" }
    rules:                      # rule_id -> [technique ids]
      injection.command: [T1059.007]

Everything degrades gracefully if the file is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

import yaml

_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_map.yaml"
_ATTACK_BASE = "https://attack.mitre.org/techniques/"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        # T1059.007 -> /techniques/T1059/007 ; T1059 -> /techniques/T1059
        return _ATTACK_BASE + self.id.replace(".", "/")

    @property
    def short(self) -> str:
        return f"{self.id} {self.name}"


@lru_cache(maxsize=1)
def _load() -> tuple[Dict[str, Technique], Dict[str, List[str]]]:
    if not _MAP_PATH.exists():
        return {}, {}
    try:
        data = yaml.safe_load(_MAP_PATH.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}, {}
    techniques: Dict[str, Technique] = {}
    for tid, info in (data.get("techniques") or {}).items():
        if isinstance(info, dict):
            techniques[str(tid)] = Technique(str(tid), str(info.get("name", tid)), str(info.get("tactic", "")))
    rules: Dict[str, List[str]] = {}
    for rid, tids in (data.get("rules") or {}).items():
        if isinstance(tids, list):
            rules[str(rid)] = [str(t) for t in tids]
        elif isinstance(tids, str):
            rules[str(rid)] = [tids]
    return techniques, rules


def techniques_for(rule_id: str) -> List[str]:
    """Technique ids mapped to a rule (empty if none)."""
    _, rules = _load()
    return list(rules.get(rule_id, []))


def technique(tid: str) -> Technique:
    """Catalog lookup; returns a placeholder Technique if unknown."""
    techniques, _ = _load()
    return techniques.get(tid, Technique(tid, tid, ""))


def all_techniques() -> Dict[str, Technique]:
    return dict(_load()[0])


def tactic_of(tid: str) -> str:
    return technique(tid).tactic

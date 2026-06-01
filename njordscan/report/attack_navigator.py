"""Export findings as a MITRE ATT&CK Navigator layer.

Produces a layer JSON you can load directly into the official ATT&CK Navigator
(https://mitre-attack.github.io/attack-navigator/) to see your app's attack
surface as a heatmap — techniques highlighted by how many findings map to them.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, List

from .. import __version__
from ..core.orchestrator import ScanResult
from ..knowledge.attack import technique


def build_layer(result: ScanResult) -> Dict[str, Any]:
    counts: Dict[str, int] = defaultdict(int)
    rules_by_tech: Dict[str, set] = defaultdict(set)
    for f in result.findings:
        for tid in f.attack:
            counts[tid] += 1
            rules_by_tech[tid].add(f.rule_id)

    max_score = max(counts.values(), default=1)
    techniques: List[Dict[str, Any]] = []
    for tid, score in sorted(counts.items(), key=lambda kv: -kv[1]):
        t = technique(tid)
        rules = ", ".join(sorted(rules_by_tech[tid]))
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "enabled": True,
            "comment": f"{score} finding(s) — {t.name} [{t.tactic}]. Rules: {rules}",
            "metadata": [{"name": "njordscan-findings", "value": str(score)}],
        })

    project_name = result.project.root.name
    return {
        "name": f"NjordScan — {project_name}",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": (
            f"Attack surface of {project_name} from a NjordScan v{__version__} scan: "
            f"{result.total} findings across {len(techniques)} ATT&CK techniques. "
            "Score = number of findings mapping to each technique."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe6e6", "#ff8c66", "#cc0000"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [
            {"label": "few findings", "color": "#ffe6e6"},
            {"label": "many findings", "color": "#cc0000"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "sorting": 3,
    }


def render_attack_navigator(result: ScanResult) -> str:
    return json.dumps(build_layer(result), indent=2, ensure_ascii=False)

"""SARIF 2.1.0 reporter for GitHub code scanning and other SARIF consumers.

Includes rule metadata, CWE tags, security-severity scores, and taint flow as
SARIF code flows so reviewers see the source→sink path inline.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .. import __version__
from ..core.finding import Finding
from ..core.orchestrator import ScanResult
from ..knowledge import all_rules

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _rules_metadata() -> List[Dict[str, Any]]:
    from ..knowledge.attack import techniques_for

    rules = []
    for rule in all_rules():
        tags = ["security"]
        if rule.cwe:
            tags.append(f"external/cwe/{rule.cwe.lower()}")
        attack = techniques_for(rule.id)
        tags += [f"attack/{t}" for t in attack]
        rules.append({
            "id": rule.id,
            "name": rule.id.replace(".", "_"),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.why},
            "helpUri": rule.references[0] if rule.references else "https://github.com/nimdy/njordscan",
            "help": {"text": f"{rule.why}\n\nFix: {rule.fix}"},
            "defaultConfiguration": {"level": rule.severity.sarif_level},
            "properties": {
                "tags": tags,
                "security-severity": str(rule.severity.security_severity),
                "cwe": rule.cwe or "",
                "owasp": rule.owasp or "",
                "mitre-attack": attack,
            },
        })
    return rules


def _result(finding: Finding) -> Dict[str, Any]:
    region = {"startLine": max(finding.line, 1)}
    if finding.column:
        region["startColumn"] = finding.column
    if finding.code_snippet:
        region["snippet"] = {"text": finding.code_snippet}

    result: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": finding.effective_severity.sarif_level,
        "message": {"text": finding.message or finding.title},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": region,
            }
        }],
        "partialFingerprints": {"njordscan/v1": finding.fingerprint},
        "properties": {"confidence": finding.confidence},
    }

    if finding.taint_flow:
        locations = []
        for step in finding.taint_flow:
            locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": step.file},
                        "region": {"startLine": max(step.line, 1), "snippet": {"text": step.code}},
                    },
                    "message": {"text": f"{step.kind}: {step.label}"},
                }
            })
        result["codeFlows"] = [{"threadFlows": [{"locations": locations}]}]
    return result


def build_sarif(result: ScanResult) -> Dict[str, Any]:
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "NjordScan",
                "version": __version__,
                "informationUri": "https://github.com/nimdy/njordscan",
                "rules": _rules_metadata(),
            }
        },
        "results": [_result(f) for f in result.findings],
    }
    # Attack paths are a cross-result correlation, so they live at the run level as a
    # property (per the SARIF guidance to keep individual results atomic).
    if result.attack_paths:
        run["properties"] = {"njordscan/attackPaths": [p.to_dict() for p in result.attack_paths]}
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False)

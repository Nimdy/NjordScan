"""JSON reporter — stable, machine-readable output for CI and tooling."""

from __future__ import annotations

import json
from typing import Any, Dict

from .. import __version__
from ..core.orchestrator import ScanResult


def build_report(result: ScanResult) -> Dict[str, Any]:
    counts = {sev.value: n for sev, n in result.counts.items()}
    return {
        "tool": "njordscan",
        "version": __version__,
        "target": str(result.project.root),
        "framework": result.project.framework,
        "summary": {
            "total": result.total,
            "by_severity": counts,
            "files_scanned": result.files_scanned,
            "duration_seconds": round(result.duration_s, 3),
            "errors": result.errors,
        },
        "attack_paths": [p.to_dict() for p in result.attack_paths],
        "findings": [f.to_dict() for f in result.findings],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(build_report(result), indent=2, ensure_ascii=False)

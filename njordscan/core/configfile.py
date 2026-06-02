"""Project config file (``.njordscan.yml``).

Lets a team commit their scan settings so everyone (and CI) runs the same checks.
CLI flags always win over the file. Everything is optional.

Example ``.njordscan.yml``:

    min_severity: low
    fail_on: high
    ignore:
      - "**/legacy/**"
    skip_detectors: [runtime]
    disable_rules:                 # silence specific rules you've reviewed
      - react.unsafe-target-blank
    severity:                      # override a rule's severity
      crypto.weak-hash: high
    baseline: .njordscan-baseline.json
    ai:
      provider: ollama
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

CONFIG_NAMES = (".njordscan.yml", ".njordscan.yaml", "njordscan.yml")

STARTER = """\
# NjordScan configuration — https://github.com/nimdy/njordscan
# All keys are optional. CLI flags override these values.

# Hide findings below this severity (info|low|medium|high|critical)
min_severity: info

# Make `njordscan scan` exit non-zero (for CI) at or above this severity
# fail_on: high

# Extra ignore globs (added to the sensible defaults)
ignore: []

# Detectors to skip entirely (e.g. secrets, taint, patterns, dependencies)
skip_detectors: []

# Rules you've reviewed and want to silence everywhere
disable_rules: []

# Override a rule's severity, e.g.  crypto.weak-hash: high
severity: {}

# Path to a baseline file (only fail on NEW findings). Create with: njordscan scan --update-baseline
# baseline: .njordscan-baseline.json

# Optional AI explanations (off unless you also pass --explain-with-ai)
# ai:
#   provider: ollama   # ollama | claude | openai
"""


@dataclass
class FileConfig:
    min_severity: Optional[str] = None
    fail_on: Optional[str] = None
    ignore: List[str] = field(default_factory=list)
    skip_detectors: List[str] = field(default_factory=list)
    only_detectors: Optional[List[str]] = None
    disable_rules: List[str] = field(default_factory=list)
    severity: Dict[str, str] = field(default_factory=dict)
    baseline: Optional[str] = None
    ai_provider: Optional[str] = None
    source: Optional[Path] = None


def find_config(start: Path) -> Optional[Path]:
    """Look for a config file in the target dir, then its parents up to the repo root."""
    start = start.resolve()
    candidates = [start, *start.parents]
    for d in candidates:
        for name in CONFIG_NAMES:
            p = d / name
            if p.is_file():
                return p
        if (d / ".git").exists():  # stop at the repo root
            break
    return None


def load_config_file(path: Path) -> FileConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return FileConfig(source=path)
    if not isinstance(data, dict):
        return FileConfig(source=path)
    ai = data.get("ai") or {}
    return FileConfig(
        min_severity=data.get("min_severity"),
        fail_on=data.get("fail_on"),
        ignore=list(data.get("ignore", []) or []),
        skip_detectors=list(data.get("skip_detectors", []) or []),
        only_detectors=list(data["only_detectors"]) if data.get("only_detectors") else None,
        disable_rules=list(data.get("disable_rules", []) or []),
        severity=dict(data.get("severity", {}) or {}),
        baseline=data.get("baseline"),
        ai_provider=ai.get("provider") if isinstance(ai, dict) else None,
        source=path,
    )

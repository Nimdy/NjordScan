"""Baseline support — adopt NjordScan into an existing repo without drowning.

A baseline is a snapshot of the findings you've decided to accept (or fix later).
On later scans, baselined findings are hidden and don't trip ``--fail-on``, so CI
only fails on *new* problems. Findings are matched by their stable fingerprint
(rule + file + line + code), so cosmetic edits elsewhere don't resurrect them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set, Tuple

from .. import __version__
from .finding import Finding


@dataclass
class Baseline:
    fingerprints: Set[str]

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fps = {str(f) for f in data.get("fingerprints", [])}
        except (OSError, json.JSONDecodeError, AttributeError):
            fps = set()
        return cls(fingerprints=fps)

    def partition(self, findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
        """Return (new_findings, known_findings) against this baseline."""
        new, known = [], []
        for f in findings:
            (known if f.fingerprint in self.fingerprints else new).append(f)
        return new, known


def write_baseline(path: Path, findings: List[Finding]) -> int:
    """Persist the current findings as the accepted baseline. Returns the count."""
    payload = {
        "tool": "njordscan",
        "version": __version__,
        "fingerprints": sorted({f.fingerprint for f in findings}),
        # human-readable index so the file is reviewable in a PR
        "findings": sorted(
            {f"{f.fingerprint}  {f.effective_severity.value:8} {f.rule_id}  {f.location}" for f in findings}
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return len(payload["fingerprints"])

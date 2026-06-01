"""Scan history — store each scan so you can see issues appear, get fixed, or linger.

Snapshots are written to ``<project>/.njordscan/history/<timestamp>.json`` (that
directory is gitignored by default). Full scans are recorded automatically; the
``results`` command lists them and diffs any two by finding fingerprint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .. import __version__
from .orchestrator import ScanResult

_KEEP = 50  # cap snapshots so the dir doesn't grow unbounded


def _history_dir(project_root: Path) -> Path:
    return project_root / ".njordscan" / "history"


@dataclass
class Snapshot:
    id: str
    timestamp: str
    total: int
    counts: Dict[str, int]
    findings: List[Dict] = field(default_factory=list)

    @property
    def fingerprints(self) -> Dict[str, Dict]:
        return {f["fingerprint"]: f for f in self.findings}


def record(result: ScanResult) -> Optional[Path]:
    """Persist a snapshot of this scan. Returns the path, or None on failure."""
    root = result.project.root
    ts = datetime.now(timezone.utc)
    try:
        d = _history_dir(root)
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    # microseconds make ids unique AND chronologically sortable by filename
    snap_id = ts.strftime("%Y%m%d-%H%M%S-%f")
    payload = {
        "id": snap_id,
        "tool_version": __version__,
        "timestamp": ts.isoformat(),
        "total": result.total,
        "counts": {s.value: n for s, n in result.counts.items()},
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "severity": f.effective_severity.value,
                "file": f.file,
                "line": f.line,
                "title": f.title,
            }
            for f in result.findings
        ],
    }
    try:
        path = d / f"{snap_id}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _prune(d)
        return path
    except OSError:
        return None


def _prune(d: Path) -> None:
    snaps = sorted(d.glob("*.json"))
    for old in snaps[:-_KEEP]:
        try:
            old.unlink()
        except OSError:
            pass


def list_snapshots(project_root: Path) -> List[Snapshot]:
    d = _history_dir(project_root)
    if not d.exists():
        return []
    out: List[Snapshot] = []
    for path in sorted(d.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append(Snapshot(
            id=str(data.get("id", path.stem)),
            timestamp=str(data.get("timestamp", "")),
            total=int(data.get("total", 0)),
            counts=dict(data.get("counts", {})),
            findings=list(data.get("findings", [])),
        ))
    return out


def load_snapshot(project_root: Path, snap_id: str) -> Optional[Snapshot]:
    for s in list_snapshots(project_root):
        if s.id == snap_id or s.id.startswith(snap_id):
            return s
    return None


@dataclass
class Diff:
    new: List[Dict]
    fixed: List[Dict]
    persistent: List[Dict]


def compare(old: Snapshot, new: Snapshot) -> Diff:
    old_fp = old.fingerprints
    new_fp = new.fingerprints
    return Diff(
        new=[f for fp, f in new_fp.items() if fp not in old_fp],
        fixed=[f for fp, f in old_fp.items() if fp not in new_fp],
        persistent=[f for fp, f in new_fp.items() if fp in old_fp],
    )

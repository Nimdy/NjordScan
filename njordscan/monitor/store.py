"""Local persistence for the operational dashboard.

A project registry + per-project scan snapshots + an alert feed, all as plain JSON
under ``~/.njordscan/monitor/`` — no database, no account. Reuses the scan-history
:class:`Snapshot` and :func:`compare` so trends/diffs are identical to ``njordscan
results``.

Layout:
    ~/.njordscan/monitor/
      projects.json                 # the registry
      alerts.json                   # the alert feed (newest first)
      <project-id>/snapshots/*.json # one snapshot per scan (history.py payload format)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.history import Snapshot, compare  # noqa: F401  (compare re-exported for callers)
from ..core.paths import user_data_dir

_KEEP = 100  # snapshots kept per project


def monitor_dir() -> Path:
    return user_data_dir() / "monitor"


def _registry_path() -> Path:
    return monitor_dir() / "projects.json"


def _alerts_path() -> Path:
    return monitor_dir() / "alerts.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _save(path: Path, data: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


# --- project registry ------------------------------------------------------- #
def list_projects() -> List[Dict[str, Any]]:
    return list(_load(_registry_path(), []))


def get_project(pid: str) -> Optional[Dict[str, Any]]:
    return next((p for p in list_projects() if p.get("id") == pid), None)


def add_project(target: str, mode: str = "path", name: str = "", interval_minutes: int = 1440) -> Dict[str, Any]:
    target = (target or "").strip()
    projects = list_projects()
    proj = {
        "id": uuid.uuid4().hex[:12],
        "name": name.strip() or _default_name(target),
        "target": target,
        "mode": mode if mode in ("path", "git", "url") else "path",
        "interval_minutes": max(5, int(interval_minutes or 1440)),
        "added_at": _now(),
        "last_scan": None,
        "last_status": "never scanned",
    }
    projects.append(proj)
    _save(_registry_path(), projects)
    return proj


def update_project(pid: str, **fields: Any) -> None:
    projects = list_projects()
    for p in projects:
        if p.get("id") == pid:
            p.update(fields)
    _save(_registry_path(), projects)


def remove_project(pid: str) -> None:
    _save(_registry_path(), [p for p in list_projects() if p.get("id") != pid])
    import shutil
    shutil.rmtree(monitor_dir() / pid, ignore_errors=True)


def _default_name(target: str) -> str:
    t = target.rstrip("/")
    if "://" in t:
        return t.split("://", 1)[1].split("/", 1)[0]
    return Path(t).name or t


# --- per-project snapshots -------------------------------------------------- #
def _snap_dir(pid: str) -> Path:
    return monitor_dir() / pid / "snapshots"


def record_snapshot(pid: str, payload: Dict[str, Any]) -> None:
    d = _snap_dir(pid)
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{payload['id']}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        snaps = sorted(d.glob("*.json"))
        for old in snaps[:-_KEEP]:
            old.unlink(missing_ok=True)
    except OSError:
        pass


def list_snapshots(pid: str) -> List[Snapshot]:
    d = _snap_dir(pid)
    out: List[Snapshot] = []
    if not d.exists():
        return out
    for path in sorted(d.glob("*.json")):
        data = _load(path, None)
        if not isinstance(data, dict):
            continue
        out.append(Snapshot(
            id=str(data.get("id", path.stem)), timestamp=str(data.get("timestamp", "")),
            total=int(data.get("total", 0)), counts=dict(data.get("counts", {})),
            findings=list(data.get("findings", [])),
        ))
    return out


def latest_snapshot(pid: str) -> Optional[Snapshot]:
    snaps = list_snapshots(pid)
    return snaps[-1] if snaps else None


def previous_snapshot(pid: str) -> Optional[Snapshot]:
    snaps = list_snapshots(pid)
    return snaps[-2] if len(snaps) >= 2 else None


# --- alerts ----------------------------------------------------------------- #
def add_alerts(entries: List[Dict[str, Any]]) -> None:
    if not entries:
        return
    feed = list(_load(_alerts_path(), []))
    feed = entries + feed
    _save(_alerts_path(), feed[:200])


def list_alerts(limit: int = 100) -> List[Dict[str, Any]]:
    return list(_load(_alerts_path(), []))[:limit]

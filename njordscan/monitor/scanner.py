"""Scan a registered project, record a snapshot, and raise alerts on new issues.

The "predict over time" half of the operational dashboard: it runs the normal scan
engine on a project, stores the result as a snapshot (history.py format), and diffs it
against the previous snapshot so a *newly appeared* critical/high becomes an alert.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import store


def _snapshot_payload(result) -> Dict[str, Any]:
    from .. import __version__
    ts = datetime.now(timezone.utc)
    return {
        "id": ts.strftime("%Y%m%d-%H%M%S-%f"),
        "tool_version": __version__,
        "timestamp": ts.isoformat(),
        "total": result.total,
        "counts": {s.value: n for s, n in result.counts.items()},
        "findings": [
            {"fingerprint": f.fingerprint, "rule_id": f.rule_id,
             "severity": f.effective_severity.value, "file": f.file,
             "line": f.line, "title": f.title}
            for f in result.findings
        ],
    }


def _alerts(proj: Dict[str, Any], prev, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if prev is None:                       # first scan: surface existing CRITICALs only (avoid noise)
        candidates = [f for f in payload["findings"] if f.get("severity") == "critical"]
        kind = "first-scan"
    else:                                  # later scans: anything NEW that's critical or high
        seen = set(prev.fingerprints.keys())
        candidates = [f for f in payload["findings"]
                      if f["fingerprint"] not in seen and f.get("severity") in ("critical", "high")]
        kind = "new-finding"
    return [{
        "ts": payload["timestamp"], "project_id": proj["id"], "project": proj.get("name", ""),
        "severity": f.get("severity", ""), "rule_id": f.get("rule_id", ""),
        "title": f.get("title", ""), "location": f"{f.get('file', '')}:{f.get('line', '')}",
        "kind": kind,
    } for f in candidates]


def scan_project(proj: Dict[str, Any]) -> Dict[str, Any]:
    """Scan one registered project; record a snapshot + alerts. Returns a status dict.
    Never raises — failures are recorded on the project's last_status."""
    from ..core.config import Config
    from ..core.orchestrator import Orchestrator

    pid, target, mode = proj["id"], proj["target"], proj.get("mode", "path")
    tmp: Optional[Path] = None
    try:
        if mode == "url":
            tmp = Path(tempfile.mkdtemp(prefix="njmon-url-"))
            cfg = Config(target=tmp, url=target, allow_private=bool(proj.get("allow_private")))
        elif mode == "git":
            tmp = Path(tempfile.mkdtemp(prefix="njmon-git-"))
            subprocess.run(["git", "clone", "--depth", "1", "--no-tags", "--", target, str(tmp)],
                           check=True, capture_output=True, timeout=300)
            cfg = Config(target=tmp)
        else:
            p = Path(target).expanduser()
            if not p.is_dir():
                store.update_project(pid, last_status="path not found")
                return {"ok": False, "error": f"path not found: {p}"}
            cfg = Config(target=p.resolve())

        prev = store.latest_snapshot(pid)          # capture BEFORE recording the new one
        result = asyncio.run(Orchestrator(cfg).run())
        payload = _snapshot_payload(result)
        store.record_snapshot(pid, payload)
        new_alerts = _alerts(proj, prev, payload)
        store.add_alerts(new_alerts)
        store.update_project(pid, last_scan=payload["timestamp"],
                             last_counts=payload["counts"],
                             last_status=f"{payload['total']} findings")
        return {"ok": True, "total": payload["total"], "new_alerts": len(new_alerts)}
    except subprocess.CalledProcessError:
        store.update_project(pid, last_status="git clone failed")
        return {"ok": False, "error": "git clone failed"}
    except subprocess.TimeoutExpired:
        store.update_project(pid, last_status="scan timed out")
        return {"ok": False, "error": "timed out"}
    except Exception as exc:  # noqa: BLE001
        store.update_project(pid, last_status=f"error: {type(exc).__name__}")
        return {"ok": False, "error": str(exc)}
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

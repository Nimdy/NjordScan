#!/usr/bin/env python3
"""NjordScan Simulation Lab — Purple Dashboard server.

A dependency-free (Python standard library only) web server that visualises the
whole range: the segmented network topology, the red team's techniques, the blue
team's live alerts, the purple ATT&CK coverage scorecard, and a live access-log
feed. It reads everything from the shared /logs volume:

  * <svc>.log      — the access-log contract the targets write (web/api/internal)
  * redteam.jsonl  — one JSON per technique verdict, written by the red-team run
  * predict.json   — NjordScan's JSON scan output (optional; the "predicted" column)

Blue-team alerts are produced LIVE by importing the actual blue-team detector
(detect.analyze_log_dir), so the dashboard and `make blueteam` always agree.

No frameworks, no CDN, fully offline. Serves index.html + GET /api/state (JSON).
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

# The blue-team detector is copied next to this file in the image; import it so the
# dashboard runs the exact same detection rules the CLI blue team does.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect  # noqa: E402

LOG_DIR = os.environ.get("LOG_DIR", "/logs")
PORT = int(os.environ.get("PORT", "8080"))
HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Static topology of the range (matches docker-compose).
# ---------------------------------------------------------------------------
TOPOLOGY = {
    "networks": ["labnet (DMZ)", "internal-net (segmented)"],
    "services": [
        {"name": "web", "label": "lab-web", "role": "target", "networks": ["labnet", "internal-net"],
         "blurb": "vulnerable storefront — the foothold (RCE) and the bridge to the internal tier"},
        {"name": "api", "label": "lab-api", "role": "target", "networks": ["labnet"],
         "blurb": "vulnerable JSON/AI API — DAST target, unauthenticated AI endpoint"},
        {"name": "internal", "label": "lab-internal", "role": "crown-jewels", "networks": ["internal-net"],
         "blurb": "segmented BackOffice tier — the customer datastore, reachable only by pivoting through web"},
        {"name": "redteam", "label": "lab-redteam", "role": "attacker", "networks": ["labnet"],
         "blurb": "attacker box — no route to the internal tier, must pivot through the web RCE"},
        {"name": "blueteam", "label": "lab-blueteam", "role": "defender", "networks": ["labnet"],
         "blurb": "mini-SIEM — tails the access logs and raises MITRE-mapped alerts"},
    ],
}

# ---------------------------------------------------------------------------
# Activity catalog — the lab's known technique set, mapping each activity to the
# red-team ATT&CK id(s) and the blue-team rule(s) that should catch it. This is
# what makes the purple scorecard honest: where red and blue legitimately use
# different ATT&CK ids for the same activity we still correlate them, and a
# genuine blind spot (cookie theft isn't visible in an access log) shows as a real
# gap rather than being hidden.
# ---------------------------------------------------------------------------
ACTIVITY_CATALOG = [
    {"key": "recon", "name": "Recon / scanning", "phase": "Recon", "red": ["T1595.002"],
     "blue_rules": ["scanner-tooling-ua", "automated-client-ua"]},
    {"key": "open_redirect", "name": "Open redirect", "phase": "Initial Access", "red": ["T1566.002"],
     "blue_rules": ["open-redirect"]},
    {"key": "xss", "name": "Reflected XSS", "phase": "Execution", "red": ["T1059.007"], "blue_rules": ["reflected-xss"]},
    {"key": "rce", "name": "OS command injection → RCE", "phase": "Execution", "red": ["T1059.004"],
     "blue_rules": ["os-command-injection"]},
    {"key": "verbose", "name": "Verbose error / info leak", "phase": "Discovery", "red": ["T1592.002", "T1592"],
     "blue_rules": ["verbose-error"]},
    {"key": "cookie", "name": "Insecure session cookie", "phase": "Credential Access", "red": ["T1539"], "blue_rules": [],
     "note": "not visible in an access log — a real blue-team blind spot"},
    {"key": "pivot", "name": "Lateral movement (pivot to internal)", "phase": "Lateral Movement", "red": ["T1210"],
     "blue_rules": ["internal-tier-access"]},
    {"key": "dow", "name": "Denial of wallet", "phase": "Impact", "red": ["T1499.003"],
     "blue_rules": ["denial-of-wallet-burst"]},
]

# MITRE kill-chain ordering for the attack-flow view.
PHASE_ORDER = ["Recon", "Initial Access", "Execution", "Discovery",
               "Credential Access", "Lateral Movement", "Impact"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError:
        pass
    return out


def _predicted_attack_ids() -> List[str]:
    """ATT&CK technique ids NjordScan flagged, from an optional predict.json
    (its --format json scan output): findings[].attack[] + attack_paths[].techniques[]."""
    path = Path(LOG_DIR) / "predict.json"
    ids: set = set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    for v in (data.get("vulnerabilities") or data.get("findings") or []):
        if isinstance(v, dict):
            for t in (v.get("attack") or []):
                if isinstance(t, str):
                    ids.add(t)
    for p in (data.get("attack_paths") or []):
        if isinstance(p, dict):
            for t in (p.get("techniques") or []):
                if isinstance(t, str):
                    ids.add(t)
    return sorted(ids)


def _parents(ids) -> set:
    """Normalise ATT&CK ids to their parent technique (T1059.004 -> T1059) so a
    sub-technique on one side still matches the parent on the other."""
    out = set()
    for t in ids:
        out.add(t)
        out.add(t.split(".")[0])
    return out


def _read_access_logs() -> List[Dict[str, Any]]:
    """Recent access-log lines across all <svc>.log, newest first."""
    rows: List[Dict[str, Any]] = []
    for path in detect.discover_logs(LOG_DIR):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    ev = detect.Event.from_json(line)
                    if ev is None:
                        continue
                    rows.append({"ts": ev.ts, "svc": ev.svc, "ip": ev.ip,
                                 "method": ev.method, "path": ev.path,
                                 "query": ev.query, "status": ev.status})
        except OSError:
            continue
    rows.sort(key=lambda r: r.get("ts") or "", reverse=True)
    return rows


def build_state() -> Dict[str, Any]:
    # --- blue team: run the real detector live over the logs -------------------
    det, alerts = detect.analyze_log_dir(LOG_DIR)
    alert_dicts = [detect.alert_to_dict(a) for a in alerts]
    alert_dicts.sort(key=lambda a: a.get("ts") or "", reverse=True)
    fired_rules = {a["rule"] for a in alert_dicts}

    # --- red team --------------------------------------------------------------
    red = _read_jsonl(Path(LOG_DIR) / "redteam.jsonl")
    landed = sum(1 for r in red if r.get("verdict") == "pass")

    # --- access logs + per-service activity ------------------------------------
    logs = _read_access_logs()
    svc_events: Dict[str, int] = {}
    for r in logs:
        svc_events[r["svc"]] = svc_events.get(r["svc"], 0) + 1
    services = []
    for s in TOPOLOGY["services"]:
        ev = svc_events.get(s["name"], 0)
        services.append({**s, "events": ev, "active": ev > 0})

    # --- purple scorecard ------------------------------------------------------
    predicted = _parents(_predicted_attack_ids())
    have_predict = bool(predicted)
    attempted_ids = _parents(r.get("mitre", "") for r in red if r.get("mitre"))
    scorecard = []
    for act in ACTIVITY_CATALOG:
        red_parents = _parents(act["red"])
        attempted = bool(red_parents & attempted_ids)
        landed_act = any(r.get("verdict") == "pass" and r.get("mitre", "").split(".")[0] in red_parents
                         for r in red)
        detected = any(rule in fired_rules for rule in act["blue_rules"])
        predicted_act = bool(red_parents & predicted) if have_predict else None
        # per-activity drill-down: the red techniques and blue alerts that map to it
        red_for = [r for r in red if r.get("mitre", "").split(".")[0] in red_parents]
        blue_for = [a for a in alert_dicts if a["rule"] in act["blue_rules"]]
        scorecard.append({
            "key": act["key"], "name": act["name"], "phase": act["phase"], "mitre": act["red"][0],
            "predicted": predicted_act, "attempted": attempted,
            "landed": landed_act, "detected": detected,
            "gap": attempted and not detected, "note": act.get("note", ""),
            "red_detail": red_for, "blue_detail": blue_for[:25],
        })

    return {
        "ts": _now(),
        "topology": {"networks": TOPOLOGY["networks"], "services": services},
        "red": {"techniques": sorted(red, key=lambda r: r.get("num", 0)),
                "landed": landed, "total": len(red)},
        "blue": {"alerts": alert_dicts[:120],
                 "by_severity": dict(det.alerts_by_severity),
                 "by_rule": dict(det.alerts_by_rule),
                 "events": det.events_seen, "total": det.total_alerts},
        "scorecard": scorecard,
        "phases": PHASE_ORDER,
        "have_predict": have_predict,
        "logs": logs[:120],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _stream(self) -> None:
        """Server-Sent Events: push a fresh state snapshot every ~2s until the
        client disconnects. ThreadingHTTPServer gives each stream its own (daemon)
        thread, so this blocking loop never holds up other requests."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            while True:
                try:
                    payload = json.dumps(build_state())
                except Exception as exc:  # noqa: BLE001
                    payload = json.dumps({"error": str(exc)})
                self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                time.sleep(2.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # client went away

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                body = (HERE / "index.html").read_bytes()
            except OSError:
                body = b"<h1>dashboard index.html missing</h1>"
            return self._send(200, body, "text/html; charset=utf-8")
        if path == "/api/state":
            try:
                body = json.dumps(build_state()).encode("utf-8")
            except Exception as exc:  # noqa: BLE001 - the dashboard must never 500-crash
                body = json.dumps({"error": str(exc)}).encode("utf-8")
            return self._send(200, body, "application/json")
        if path == "/api/stream":
            return self._stream()
        if path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET


def main() -> int:
    print(f"[dashboard] serving on http://0.0.0.0:{PORT}  (logs: {LOG_DIR})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

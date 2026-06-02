#!/usr/bin/env python3
"""
NjordScan Simulation Lab — Blue-Team Detector / mini-SIEM
========================================================

Pure Python 3 standard library. No third-party dependencies.

It tails the JSON access logs that the two vulnerable targets append to (one
JSON object per HTTP request, one per line) and runs a set of detection rules
over each event. Matching events become structured ALERTS with a name, a
severity and a MITRE ATT&CK technique id.

LOG CONTRACT (one JSON line per request, written by each vulnerable target):

    {
      "ts":     "<ISO8601>",
      "svc":    "web" | "api",
      "ip":     "<remote ip>",
      "method": "GET" | "POST" | ...,
      "path":   "/search",
      "query":  "q=<script>alert(1)</script>",   # raw, url-decoded
      "status": 200,
      "ua":     "<user-agent>",
      "ref":    "<referer>",
      "body":   "<short request body or empty>"   # POST only, ~500 chars
    }

Any field may be an empty string. Malformed lines are skipped (and counted).

Usage
-----
    python3 detect.py --once  --log-dir /tmp/logs     # process & exit (CI/tests)
    python3 detect.py --follow                        # tail -f the logs (default)
    LOG_DIR=/logs python3 detect.py                   # env override of the dir

Run with --help for the full option list.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Severity ordering (used for sorting + the summary table)
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


_COLOR = _supports_color()
_SEV_COLOR = {
    "CRITICAL": "\033[1;35m",  # bright magenta
    "HIGH": "\033[1;31m",      # bright red
    "MEDIUM": "\033[1;33m",    # bright yellow
    "LOW": "\033[1;36m",       # bright cyan
    "INFO": "\033[0;37m",      # grey
}
_RESET = "\033[0m"


def _color(text: str, sev: str) -> str:
    if not _COLOR:
        return text
    return f"{_SEV_COLOR.get(sev, '')}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------
@dataclass
class Event:
    """A single parsed access-log line."""

    ts: str = ""
    svc: str = ""
    ip: str = ""
    method: str = ""
    path: str = ""
    query: str = ""
    status: int = 0
    ua: str = ""
    ref: str = ""
    body: str = ""
    raw: str = ""

    @property
    def target(self) -> str:
        """path + ?query — the thing rules pattern-match against."""
        return f"{self.path}?{self.query}" if self.query else self.path

    @property
    def haystack(self) -> str:
        """Everything an injection might hide in, lower-cased for matching."""
        return f"{self.path} {self.query} {self.body}".lower()

    @classmethod
    def from_json(cls, line: str) -> Optional["Event"]:
        line = line.strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(obj, dict):
            return None

        def s(key: str) -> str:
            v = obj.get(key, "")
            return v if isinstance(v, str) else ("" if v is None else str(v))

        status_raw = obj.get("status", 0)
        try:
            status = int(status_raw)
        except (TypeError, ValueError):
            status = 0

        return cls(
            ts=s("ts"),
            svc=s("svc"),
            ip=s("ip"),
            method=s("method"),
            path=s("path"),
            query=s("query"),
            status=status,
            ua=s("ua"),
            ref=s("ref"),
            body=s("body"),
            raw=line,
        )


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------
@dataclass
class Alert:
    rule: str
    severity: str
    technique: str          # MITRE ATT&CK technique id
    event: Event
    evidence: str

    def line(self) -> str:
        ev = self.event
        loc = ev.target
        if len(loc) > 80:
            loc = loc[:77] + "..."
        evidence = self.evidence
        if len(evidence) > 120:
            evidence = evidence[:117] + "..."
        tag = _color(
            f"[ALERT][{self.severity}][{self.technique}]", self.severity
        )
        return (
            f"{tag} {self.rule}  "
            f"svc={ev.svc or '-'} ip={ev.ip or '-'} "
            f"path={loc}  evidence={evidence!r}"
        )


# ---------------------------------------------------------------------------
# Rule infrastructure
# ---------------------------------------------------------------------------
# A "simple" rule inspects ONE event and returns evidence (str) when it fires,
# or None when it doesn't. Stateful rules (bursts) get their own handling.
SimpleMatcher = Callable[[Event], Optional[str]]


@dataclass
class Rule:
    name: str
    severity: str
    technique: str
    matcher: SimpleMatcher
    description: str = ""


def _first_match(patterns: List[re.Pattern], text: str) -> Optional[str]:
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


# --- compiled pattern sets -------------------------------------------------
# Reflected XSS: <script, onerror=, javascript:, %3Cscript and friends.
_XSS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"%3c\s*script", re.IGNORECASE),
    re.compile(r"</\s*script", re.IGNORECASE),
    re.compile(r"\bon(error|load|mouseover|click|focus|toggle)\s*=", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src", re.IGNORECASE),
    re.compile(r"<\s*svg", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
]

# SQL injection: ' OR, UNION SELECT, --, ; DROP, sleep(), OR 1=1 ...
_SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"'\s*or\s+'?\d", re.IGNORECASE),
    re.compile(r"'\s*or\s+'[^']*'\s*=\s*'", re.IGNORECASE),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"\bsleep\s*\(\s*\d", re.IGNORECASE),
    re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE),
    re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
    re.compile(r"\bdrop\s+(table|database)\b", re.IGNORECASE),
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r"--\s+", re.IGNORECASE),       # SQL line comment (needs trailing space)
    re.compile(r"%27\s*or", re.IGNORECASE),    # encoded ' or
]

# OS command injection: ;id, |, $(, backtick, &&, ;cat, %3B ...
_CMDI_PATTERNS = [
    re.compile(r";\s*(id|whoami|uname|cat|ls|pwd|nc|bash|sh|wget|curl)\b", re.IGNORECASE),
    re.compile(r"\|\s*(id|whoami|uname|cat|ls|nc|bash|sh)\b", re.IGNORECASE),
    re.compile(r"&&\s*(id|whoami|uname|cat|ls|nc|bash|sh)\b", re.IGNORECASE),
    re.compile(r"\$\(", re.IGNORECASE),                 # $(...) command substitution
    re.compile(r"`[^`]+`"),                              # `...` backticks
    re.compile(r"%3b\s*(id|whoami|cat|ls|uname)", re.IGNORECASE),  # encoded ;id
    re.compile(r"%7c\s*(id|whoami|cat|ls|uname)", re.IGNORECASE),  # encoded |cmd
    re.compile(r";\s*sleep\s+\d", re.IGNORECASE),       # ;sleep 5
    # NB: bare /etc/passwd is intentionally NOT here — that is a file-read
    # target and is classified as path-traversal. Genuine command injection
    # that reads it (e.g. $(cat /etc/passwd)) still fires via the $(...) / ;cat
    # patterns above, so it is not lost.
]

# Path traversal: ../, %2e%2e, /etc/passwd, ..%2f ...
_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e", re.IGNORECASE),
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"\.\.%5c", re.IGNORECASE),
    re.compile(r"(?:\.\.[\\/]){2,}", re.IGNORECASE),
]

# Dedicated offensive / scanning tools — a strong signal (MEDIUM).
_SCANNER_PATTERNS = [
    re.compile(r"\bnmap\b", re.IGNORECASE),
    re.compile(r"\bnikto\b", re.IGNORECASE),
    re.compile(r"\bsqlmap\b", re.IGNORECASE),
    re.compile(r"\bnjordscan\b", re.IGNORECASE),
    re.compile(r"\bdirb\b", re.IGNORECASE),
    re.compile(r"\bdirbuster\b", re.IGNORECASE),
    re.compile(r"\bgobuster\b", re.IGNORECASE),
    re.compile(r"\bwpscan\b", re.IGNORECASE),
    re.compile(r"\bmasscan\b", re.IGNORECASE),
    re.compile(r"\bzgrab\b", re.IGNORECASE),
    re.compile(r"\bnuclei\b", re.IGNORECASE),
    re.compile(r"\bhydra\b", re.IGNORECASE),
    re.compile(r"\bwfuzz\b", re.IGNORECASE),
    re.compile(r"\bffuf\b", re.IGNORECASE),
    re.compile(r"\bzaproxy\b|\bOWASP ZAP\b", re.IGNORECASE),
]

# Generic automated HTTP clients (curl/wget/scripts). Worth noting but LOW signal —
# they're how most legit automation AND opportunistic pokes both look, so they're
# INFO (and de-duped per source) so they never bury the real CRITICAL/HIGH alerts.
_GENERIC_CLIENT_PATTERNS = [
    re.compile(r"\bcurl/", re.IGNORECASE),
    re.compile(r"\bwget/", re.IGNORECASE),
    re.compile(r"python-requests", re.IGNORECASE),
    re.compile(r"\bgo-http-client\b", re.IGNORECASE),
    re.compile(r"\bokhttp\b", re.IGNORECASE),
    re.compile(r"\blibwww-perl\b", re.IGNORECASE),
    re.compile(r"\bhttpie\b", re.IGNORECASE),
    re.compile(r"\b(node-fetch|axios|java)/", re.IGNORECASE),
]

# Hosts considered "ours" for the open-redirect heuristic (NOT external).
_INTERNAL_HOST_RE = re.compile(
    r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|web|api|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"
    r"(:\d+)?$",
    re.IGNORECASE,
)

# Pull a url= / next= / return= / dest= value out of a raw query string.
_REDIRECT_PARAM_RE = re.compile(
    r"(?:^|&)(url|next|return|returnto|return_to|dest|destination|redirect|"
    r"redirect_uri|continue|to|goto|target)=([^&]+)",
    re.IGNORECASE,
)
# An absolute external URL (scheme-relative // included).
_ABS_URL_RE = re.compile(r"^(?:https?:)?//([^/?#]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Simple-rule matchers
# ---------------------------------------------------------------------------
def _m_xss(ev: Event) -> Optional[str]:
    return _first_match(_XSS_PATTERNS, ev.haystack)


def _m_sqli(ev: Event) -> Optional[str]:
    return _first_match(_SQLI_PATTERNS, ev.haystack)


def _m_cmdi(ev: Event) -> Optional[str]:
    return _first_match(_CMDI_PATTERNS, ev.haystack)


def _m_traversal(ev: Event) -> Optional[str]:
    return _first_match(_TRAVERSAL_PATTERNS, ev.haystack)


def _m_scanner(ev: Event) -> Optional[str]:
    return _first_match(_SCANNER_PATTERNS, ev.ua)


# Generic automated clients are deduped per (svc, ip): note each source once instead
# of firing on every single request, so curl/wget traffic can't bury real alerts.
_seen_clients: set = set()


def _m_generic_client(ev: Event) -> Optional[str]:
    m = _first_match(_GENERIC_CLIENT_PATTERNS, ev.ua)
    if not m:
        return None
    key = (ev.svc, ev.ip)
    if key in _seen_clients:
        return None
    _seen_clients.add(key)
    return m


def _unquote(s: str) -> str:
    """URL-decode without importing urllib for a single helper (it's stdlib,
    but the query is already documented as url-decoded; we still handle the
    case where a %-encoded redirect slipped through)."""
    try:
        from urllib.parse import unquote

        return unquote(s)
    except Exception:  # pragma: no cover - defensive
        return s


def _m_open_redirect(ev: Event) -> Optional[str]:
    """Open-redirect probe: a redirect-style param pointing at an EXTERNAL host.

    Strongly anchored to /go (target 01's open-redirect route) but also fires
    for any url=/next=/etc. param that resolves to an off-site absolute URL.
    """
    query = ev.query or ""
    for m in _REDIRECT_PARAM_RE.finditer(query):
        value = _unquote(m.group(2))
        host_m = _ABS_URL_RE.match(value.strip())
        if not host_m:
            continue
        host = host_m.group(1)
        if _INTERNAL_HOST_RE.match(host):
            continue  # redirecting to ourselves is fine
        return f"{m.group(1)}={value[:80]}"
    return None


def _m_verbose_error(ev: Event) -> Optional[str]:
    if ev.status == 500:
        return f"HTTP {ev.status} on {ev.target}"
    return None


def _m_internal_tier(ev: Event) -> Optional[str]:
    """Crown-jewel access on the SEGMENTED internal tier.

    The internal BackOffice service sits on a network that only the web tier can
    reach, and the application itself only ever calls /account there. So ANY hit
    on /admin/* is a DMZ->internal pivot landing on the customer datastore —
    lateral movement + collection, by definition. (A blocked attempt never even
    produces a log line here, so a match means the pivot LANDED.)
    """
    if ev.svc != "internal":
        return None
    p = (ev.path or "").rstrip("/")
    if p.startswith("/admin"):
        return f"internal {ev.path} reached from {ev.ip or '-'} (DMZ->internal pivot onto the datastore)"
    return None


# ---------------------------------------------------------------------------
# The rule registry (simple, per-event rules)
# ---------------------------------------------------------------------------
RULES: List[Rule] = [
    Rule(
        name="reflected-xss",
        severity="HIGH",
        technique="T1059.007",  # Command and Scripting Interpreter: JavaScript
        matcher=_m_xss,
        description="Reflected/stored XSS payload markers in path, query or body "
        "(<script, onerror=, javascript:, %3Cscript, img/svg/iframe handlers).",
    ),
    Rule(
        name="sql-injection",
        severity="HIGH",
        technique="T1190",  # Exploit Public-Facing Application
        matcher=_m_sqli,
        description="SQL injection syntax (' OR, UNION SELECT, --, ; DROP, "
        "sleep()/benchmark(), OR 1=1, information_schema).",
    ),
    Rule(
        name="os-command-injection",
        severity="CRITICAL",
        technique="T1059.004",  # Command and Scripting Interpreter: Unix Shell
        matcher=_m_cmdi,
        description="Shell metacharacters / command chaining (;id, | cmd, $(...), "
        "`...`, && cmd, %3Bid encoded) — esp. against /ping.",
    ),
    Rule(
        name="path-traversal",
        severity="HIGH",
        technique="T1083",  # File and Directory Discovery
        matcher=_m_traversal,
        description="Directory traversal sequences (../, ..\\, %2e%2e, ..%2f, "
        "/etc/passwd).",
    ),
    Rule(
        name="open-redirect",
        severity="MEDIUM",
        technique="T1190",  # Exploit Public-Facing Application
        matcher=_m_open_redirect,
        description="Redirect parameter (url=, next=, /go?url=) pointing at an "
        "external host.",
    ),
    Rule(
        name="scanner-tooling-ua",
        severity="MEDIUM",
        technique="T1595.002",  # Active Scanning: Vulnerability Scanning
        matcher=_m_scanner,
        description="Dedicated offensive/scanner User-Agent (nmap, nikto, sqlmap, "
        "njordscan, dirb, gobuster, nuclei, ffuf, ZAP, ...).",
    ),
    Rule(
        name="automated-client-ua",
        severity="INFO",
        technique="T1595.002",
        matcher=_m_generic_client,
        description="Generic automated HTTP client (curl/wget/python-requests/...). "
        "Low signal — noted once per source so it never buries the real alerts.",
    ),
    Rule(
        name="verbose-error",
        severity="LOW",
        technique="T1592",  # Gather Victim Host Information (info leak)
        matcher=_m_verbose_error,
        description="HTTP 500 response — verbose stack traces leak internals "
        "(stack frames, secrets, paths).",
    ),
    Rule(
        name="internal-tier-access",
        severity="CRITICAL",
        technique="T1210",  # Exploitation of Remote Services (lateral movement)
        matcher=_m_internal_tier,
        description="Access to the segmented internal admin tier's /admin/* "
        "endpoints — only reachable by pivoting through the DMZ web tier "
        "(lateral movement landing on the customer datastore).",
    ),
]


# ---------------------------------------------------------------------------
# Stateful rule: denial-of-wallet / brute force burst detection
# ---------------------------------------------------------------------------
@dataclass
class BurstRule:
    name: str = "denial-of-wallet-burst"
    severity: str = "HIGH"
    technique: str = "T1499.003"  # Endpoint DoS: Application Exhaustion Flood
    description: str = (
        "Request burst from one IP within a short window — flags "
        "denial-of-wallet against the unauthenticated /api/chat AI endpoint, "
        "and credential brute force against /login."
    )
    window_secs: float = 10.0
    chat_threshold: int = 5     # >N requests to /api/chat from one ip in window
    login_threshold: int = 5    # >N requests to /login (brute force)
    generic_threshold: int = 30  # >N requests to ANY single path from one ip

    # state: (ip, bucket) -> deque[timestamp]
    _hits: Dict[Tuple[str, str], Deque[float]] = field(default_factory=lambda: defaultdict(deque))
    # don't re-alert on every single request once a burst is firing; cool down
    _fired_until: Dict[Tuple[str, str], float] = field(default_factory=dict)

    def _bucket(self, ev: Event) -> Optional[Tuple[str, int, str]]:
        """Return (bucket_key, threshold, human_label) or None if not tracked."""
        p = ev.path.rstrip("/") or "/"
        if p == "/api/chat":
            return ("chat", self.chat_threshold, "/api/chat (denial-of-wallet)")
        if p in ("/login", "/api/login", "/auth/login"):
            return ("login", self.login_threshold, f"{p} (brute force)")
        # generic high-volume hammering of a single path
        return ("path:" + p, self.generic_threshold, p)

    def feed(self, ev: Event, now: float) -> Optional[Alert]:
        info = self._bucket(ev)
        if info is None:
            return None
        bucket, threshold, label = info
        key = (ev.ip or "-", bucket)

        dq = self._hits[key]
        dq.append(now)
        # evict timestamps outside the window
        cutoff = now - self.window_secs
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)
        if count <= threshold:
            return None

        # cool-down: one alert per (ip,bucket) per window, not per request
        if self._fired_until.get(key, 0.0) > now:
            return None
        self._fired_until[key] = now + self.window_secs

        evidence = (
            f"{count} requests to {label} from {ev.ip or '-'} "
            f"within {self.window_secs:.0f}s (threshold {threshold})"
        )
        return Alert(
            rule=self.name,
            severity=self.severity,
            technique=self.technique,
            event=ev,
            evidence=evidence,
        )


def _event_time(ev: Event, fallback: float) -> float:
    """Use the event's own ISO timestamp for windowing when available so that
    --once over a historical log detects bursts correctly; otherwise fall back
    to wall-clock (live --follow)."""
    if ev.ts:
        ts = ev.ts.strip()
        # Normalise a trailing Z to +00:00 for fromisoformat.
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return fallback


# ---------------------------------------------------------------------------
# Detector engine
# ---------------------------------------------------------------------------
class Detector:
    def __init__(self, emit: Callable[[Alert], None]):
        self.emit = emit
        self.burst = BurstRule()
        # stats
        self.events_seen = 0
        self.lines_skipped = 0
        self.alerts_by_rule: Dict[str, int] = defaultdict(int)
        self.alerts_by_severity: Dict[str, int] = defaultdict(int)
        self.total_alerts = 0

    def _record(self, alert: Alert) -> None:
        self.alerts_by_rule[alert.rule] += 1
        self.alerts_by_severity[alert.severity] += 1
        self.total_alerts += 1
        self.emit(alert)

    def process_line(self, line: str, wall_now: Optional[float] = None) -> None:
        ev = Event.from_json(line)
        if ev is None:
            if line.strip():
                self.lines_skipped += 1
            return
        self.events_seen += 1

        # per-event simple rules
        for rule in RULES:
            evidence = rule.matcher(ev)
            if evidence is not None:
                self._record(
                    Alert(
                        rule=rule.name,
                        severity=rule.severity,
                        technique=rule.technique,
                        event=ev,
                        evidence=evidence,
                    )
                )

        # stateful burst rule (uses event ts for windowing when present)
        now = _event_time(ev, wall_now if wall_now is not None else time.time())
        burst_alert = self.burst.feed(ev, now)
        if burst_alert is not None:
            self._record(burst_alert)

    # --- summary table -----------------------------------------------------
    def summary_text(self) -> str:
        lines: List[str] = []
        bar = "=" * 60
        lines.append(bar)
        lines.append("DETECTION SUMMARY")
        lines.append(bar)
        lines.append(
            f"events parsed : {self.events_seen}    "
            f"malformed lines skipped : {self.lines_skipped}"
        )
        lines.append(f"total alerts  : {self.total_alerts}")
        lines.append("")

        # by rule
        lines.append(f"{'RULE':<26}{'SEVERITY':<10}{'TECHNIQUE':<12}{'COUNT':>6}")
        lines.append("-" * 60)
        rule_meta = {r.name: (r.severity, r.technique) for r in RULES}
        rule_meta[self.burst.name] = (self.burst.severity, self.burst.technique)
        # sort by severity then count desc
        for name in sorted(
            self.alerts_by_rule,
            key=lambda n: (SEVERITY_ORDER.get(rule_meta.get(n, ("INFO",))[0], 9),
                           -self.alerts_by_rule[n]),
        ):
            sev, tech = rule_meta.get(name, ("INFO", "-"))
            count = self.alerts_by_rule[name]
            lines.append(
                f"{name:<26}{_color(sev, sev):<10}{tech:<12}{count:>6}"
                if not _COLOR
                else f"{name:<26}{_color(f'{sev:<10}', sev)}{tech:<12}{count:>6}"
            )
        if not self.alerts_by_rule:
            lines.append("(no alerts)")
        lines.append("-" * 60)

        # by severity
        sev_parts = []
        for sev in sorted(self.alerts_by_severity, key=lambda s: SEVERITY_ORDER.get(s, 9)):
            sev_parts.append(_color(f"{sev}={self.alerts_by_severity[sev]}", sev))
        lines.append("by severity: " + ("  ".join(sev_parts) if sev_parts else "(none)"))
        lines.append(bar)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Log file discovery + tailing
# ---------------------------------------------------------------------------
def discover_logs(log_dir: str) -> List[str]:
    if not os.path.isdir(log_dir):
        return []
    out = []
    for name in sorted(os.listdir(log_dir)):
        if name.endswith(".log"):
            full = os.path.join(log_dir, name)
            if os.path.isfile(full):
                out.append(full)
    return out


def run_once(detector: Detector, log_dir: str) -> None:
    files = discover_logs(log_dir)
    if not files:
        print(f"[detect] no *.log files found in {log_dir!r}", file=sys.stderr)
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    detector.process_line(line)
        except OSError as exc:
            print(f"[detect] cannot read {path}: {exc}", file=sys.stderr)


def run_follow(detector: Detector, log_dir: str, poll: float = 0.5) -> None:
    """tail -f style: open every *.log, seek to end, and stream new lines.

    Handles files that appear after start-up, and truncation/rotation
    (when the file shrinks we re-read from the top)."""
    print(
        f"[detect] following {log_dir!r} (Ctrl-C to stop) — "
        f"{len(RULES) + 1} rules armed",
        file=sys.stderr,
    )
    handles: Dict[str, "object"] = {}
    inodes: Dict[str, int] = {}

    def ensure_open(path: str, from_start: bool = False) -> None:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
        if not from_start:
            fh.seek(0, os.SEEK_END)
        handles[path] = fh
        try:
            inodes[path] = os.fstat(fh.fileno()).st_ino
        except OSError:
            inodes[path] = -1

    # open whatever exists right now, seeking to the end (only new traffic)
    for path in discover_logs(log_dir):
        ensure_open(path)

    try:
        while True:
            # pick up newly-created log files
            for path in discover_logs(log_dir):
                if path not in handles:
                    print(f"[detect] new log file: {path}", file=sys.stderr)
                    ensure_open(path, from_start=True)

            for path, fh in list(handles.items()):
                # detect truncation / rotation
                try:
                    st = os.stat(path)
                    if st.st_ino != inodes.get(path) or st.st_size < fh.tell():
                        fh.close()
                        ensure_open(path, from_start=True)
                        fh = handles[path]
                except OSError:
                    # file vanished; drop the handle
                    try:
                        fh.close()
                    except OSError:
                        pass
                    handles.pop(path, None)
                    inodes.pop(path, None)
                    continue

                while True:
                    line = fh.readline()
                    if not line:
                        break
                    detector.process_line(line)

            time.sleep(poll)
    except KeyboardInterrupt:
        print("\n[detect] stopped.", file=sys.stderr)
        print(detector.summary_text(), file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detect.py",
        description="NjordScan blue-team detector / mini-SIEM for the simulation lab.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="Process the existing log files once and exit (CI/tests).",
    )
    mode.add_argument(
        "--follow",
        action="store_true",
        help="Tail -f the logs and alert on new traffic (default).",
    )
    p.add_argument(
        "--log-dir",
        default=os.environ.get("LOG_DIR", "/logs"),
        help="Directory containing <svc>.log access logs "
        "(default: $LOG_DIR or /logs).",
    )
    p.add_argument(
        "--list-rules",
        action="store_true",
        help="Print the rule catalogue (name, severity, MITRE id) and exit.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-alert lines; print only the summary (--once).",
    )
    return p


def print_rule_catalogue() -> None:
    print(f"{'RULE':<26}{'SEVERITY':<10}{'MITRE':<12}DESCRIPTION")
    print("-" * 100)
    for r in RULES:
        print(f"{r.name:<26}{r.severity:<10}{r.technique:<12}{r.description}")
    b = BurstRule()
    print(f"{b.name:<26}{b.severity:<10}{b.technique:<12}{b.description}")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.list_rules:
        print_rule_catalogue()
        return 0

    emitted: List[Alert] = []

    def emit(alert: Alert) -> None:
        emitted.append(alert)
        if not args.quiet:
            print(alert.line(), flush=True)  # flush: real-time SIEM output

    detector = Detector(emit)

    # default mode is --follow unless --once is given
    if args.once:
        run_once(detector, args.log_dir)
        if not args.quiet:
            print()  # spacer before summary
        print(detector.summary_text())
        return 0

    # follow mode
    run_follow(detector, args.log_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Refresh dependency advisories from OSV.dev.

``njordscan update`` queries the public OSV.dev API for npm advisories and writes
them to a user cache (``~/.njordscan/advisories.json``) that the dependencies
detector merges on top of the shipped seed — so the CVE data never goes stale.

Uses only the standard library (urllib) so it works on the core install with no
extra dependencies. TLS verification is on (urllib verifies certificates by
default); we never disable it.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import __version__
from .core import exploit as exploit_store
from .core.paths import user_advisories_path, user_patterns_dir, user_rules_dir

# Threat data older than this earns a gentle "run njordscan update" nudge on scan.
STALE_AFTER_DAYS = 21

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
# Self-updating detection feed (rules + patterns). Override with $NJORDSCAN_RULES_FEED.
RULES_FEED_URL = os.getenv(
    "NJORDSCAN_RULES_FEED",
    "https://raw.githubusercontent.com/nimdy/njordscan/v2/feed/rules-feed.json",
)

# The packages a Next.js/React/Vite developer is most likely to use. We always
# refresh these; the scanned project's own dependencies are added on top.
POPULAR_NPM = [
    "next", "react", "react-dom", "vite", "vue", "svelte", "@sveltejs/kit",
    "lodash", "axios", "express", "fastify", "koa", "nest", "@nestjs/core",
    "jsonwebtoken", "jose", "passport", "bcrypt", "cookie", "node-fetch",
    "ws", "socket.io", "mongoose", "mongodb", "pg", "mysql2", "prisma",
    "@prisma/client", "sequelize", "redis", "ioredis", "graphql", "apollo-server",
    "dompurify", "marked", "ejs", "handlebars", "pug", "serialize-javascript",
    "minimist", "qs", "semver", "moment", "undici", "form-data", "tar",
    "webpack", "esbuild", "postcss", "sharp", "formidable", "multer", "got",
]


def _query_osv(name: str, timeout: float = 15.0) -> List[Dict[str, Any]]:
    body = json.dumps({"package": {"ecosystem": "npm", "name": name}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL, data=body,
        headers={"Content-Type": "application/json", "User-Agent": f"njordscan/{__version__}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https host
        data = json.loads(resp.read().decode("utf-8"))
    vulns = data.get("vulns") or []
    return vulns if isinstance(vulns, list) else []


def _severity_of(vuln: Dict[str, Any]) -> str:
    db = vuln.get("database_specific") or {}
    sev = str(db.get("severity", "")).lower()
    if sev in ("critical", "high", "moderate", "medium", "low"):
        return "medium" if sev == "moderate" else sev
    # Fall back to a CVSS score if present.
    for s in vuln.get("severity", []) or []:
        score = str(s.get("score", ""))
        if "CVSS:3" in score:
            return "high"
    return "high"


def _ranges_for_npm(vuln: Dict[str, Any], name: str) -> Optional[Dict[str, str]]:
    """Return {'vulnerable_range','patched'} for the npm package, or None."""
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != "npm" or pkg.get("name") != name:
            continue
        for rng in affected.get("ranges", []) or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced, fixed = "0", None
            for event in rng.get("events", []) or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if fixed:
                vr = f"<{fixed}" if introduced in ("0", "0.0.0") else f">={introduced},<{fixed}"
                return {"vulnerable_range": vr, "patched": fixed}
    return None


def _to_advisory(vuln: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    ranges = _ranges_for_npm(vuln, name)
    if not ranges:
        return None
    aliases = vuln.get("aliases") or []
    cve = next((a for a in aliases if str(a).startswith("CVE-")), None)
    ghsa = next((a for a in aliases if str(a).startswith("GHSA-")), vuln.get("id"))
    return {
        "id": cve or vuln.get("id"),
        "ghsa": ghsa,
        "vulnerable_range": ranges["vulnerable_range"],
        "patched": ranges["patched"],
        "severity": _severity_of(vuln),
        "summary": (vuln.get("summary") or vuln.get("details") or "").strip()[:300],
        "references": [r.get("url") for r in (vuln.get("references") or []) if r.get("url")][:3],
    }


def refresh(package_names: List[str], progress=None) -> Dict[str, Any]:
    """Query OSV for each package; return the advisory DB dict (and write it)."""
    advisories: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[str] = []
    seen = set()
    names = [n for n in package_names if n and n not in seen and not seen.add(n)]

    for name in names:
        if progress:
            progress(name)
        try:
            vulns = _query_osv(name)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        entries = [a for v in vulns if (a := _to_advisory(v, name))]
        if entries:
            advisories[name] = entries

    db = {
        "_meta": {"source": "osv.dev", "tool_version": __version__, "packages_queried": len(names)},
        "advisories": advisories,
    }
    path = user_advisories_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(db, indent=2), encoding="utf-8")

    # Exploit intelligence: CISA KEV (actively exploited) + EPSS (exploit probability).
    cves = {str(a.get("id")) for entries in advisories.values() for a in entries
            if str(a.get("id", "")).startswith("CVE-")}
    kev_count = epss_count = 0
    try:
        kev = fetch_kev()
        epss = fetch_epss(sorted(cves))
        exploit_store.write(kev, epss)
        kev_count, epss_count = len(kev), len(epss)
    except Exception as exc:  # noqa: BLE001 — exploit intel is best-effort
        errors.append(f"exploit-intel: {exc}")

    return {"path": path, "packages_with_advisories": len(advisories),
            "total_advisories": sum(len(v) for v in advisories.values()),
            "kev_total": kev_count, "epss_scored": epss_count, "errors": errors}


def fetch_kev(timeout: float = 20.0) -> Set[str]:
    """The CISA Known Exploited Vulnerabilities catalog (set of CVE ids)."""
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": f"njordscan/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https host
        data = json.loads(resp.read().decode("utf-8"))
    return {str(v["cveID"]).upper() for v in (data.get("vulnerabilities") or []) if v.get("cveID")}


def fetch_epss(cve_ids: List[str], timeout: float = 20.0) -> Dict[str, float]:
    """EPSS scores (0-1) for the given CVE ids, batched (~100 per request)."""
    out: Dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i + 100]
        url = f"{EPSS_URL}?cve={urllib.parse.quote(','.join(batch))}"
        req = urllib.request.Request(url, headers={"User-Agent": f"njordscan/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            continue
        for row in data.get("data") or []:
            cve, score = row.get("cve"), row.get("epss")
            if cve and score is not None:
                try:
                    out[str(cve).upper()] = float(score)
                except (TypeError, ValueError):
                    pass
    return out


def data_age_days() -> Optional[float]:
    """Age (days) of the freshest refreshed threat data, or ``None`` if never run.

    Looks at the advisory cache and the exploit-intel store — whichever was
    written most recently. Used to nudge the user to ``njordscan update`` when the
    CVE/exploit picture may have moved on since their last refresh.
    """
    candidates = [user_advisories_path(), exploit_store.exploit_path(),
                  user_rules_dir(), user_patterns_dir()]
    mtimes = [p.stat().st_mtime for p in candidates if p.exists()]
    if not mtimes:
        return None
    return max(0.0, (time.time() - max(mtimes)) / 86400.0)


def staleness_hint() -> Optional[str]:
    """A one-line nudge if threat data is missing or older than ``STALE_AFTER_DAYS``."""
    age = data_age_days()
    if age is None:
        return "Threat data not yet fetched — run 'njordscan update' for live CVE + exploit intel."
    if age > STALE_AFTER_DAYS:
        return (f"Threat data is {int(age)} days old — run 'njordscan update' "
                "to refresh advisories, exploit intel, and detection rules.")
    return None


def _safe_yaml_name(name: str) -> Optional[str]:
    """Validate a feed file name as a bare ``*.yaml`` (reject anything path-like).

    We do NOT try to *repair* a suspicious name (e.g. basename it) — for a security
    tool, a feed entry that smells like path traversal is rejected outright.
    """
    base = str(name).strip()
    if not base or base.startswith(".") or ".." in base:
        return None
    if "/" in base or "\\" in base or os.path.basename(base) != base:
        return None
    if not base.endswith((".yaml", ".yml")):
        return None
    return base


def _write_feed_files(directory: Path, files: Any) -> int:
    """Write {name: yaml_text} into ``directory``; ignore unsafe names. Returns count."""
    if not isinstance(files, dict) or not files:
        return 0
    directory.mkdir(parents=True, exist_ok=True)
    written = 0
    for name, content in files.items():
        safe = _safe_yaml_name(name)
        if not safe or not isinstance(content, str):
            continue
        # Validate it parses as YAML before trusting it on disk.
        try:
            import yaml
            yaml.safe_load(content)
        except Exception:  # noqa: BLE001 — skip malformed feed entries
            continue
        (directory / safe).write_text(content, encoding="utf-8")
        written += 1
    return written


def fetch_rules_feed(url: Optional[str] = None, timeout: float = 20.0) -> Dict[str, Any]:
    """Fetch the self-updating detection feed (knowledge rules + patterns).

    The feed is a JSON manifest::

        {"version": "...", "generated": "...",
         "rules":    {"my-rules.yaml": "<yaml text>"},
         "patterns": {"my-patterns.yaml": "<yaml text>"}}

    File contents are written into ``~/.njordscan/rules`` and
    ``~/.njordscan/patterns``, which the registry and pattern engine merge on top
    of the shipped data. Names are sanitized (no path traversal) and each entry
    must parse as YAML before it is trusted. A missing feed (404) is not an error
    — it just means there is nothing newer than what shipped.
    """
    url = url or RULES_FEED_URL
    req = urllib.request.Request(url, headers={"User-Agent": f"njordscan/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — configurable https feed
        manifest = json.loads(resp.read().decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("rules feed is not a JSON object")
    n_rules = _write_feed_files(user_rules_dir(), manifest.get("rules"))
    n_patterns = _write_feed_files(user_patterns_dir(), manifest.get("patterns"))
    return {
        "version": manifest.get("version"),
        "generated": manifest.get("generated"),
        "rules_written": n_rules,
        "patterns_written": n_patterns,
        "url": url,
    }

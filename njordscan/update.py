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
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from . import __version__
from .core.paths import user_advisories_path

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

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
    return {"path": path, "packages_with_advisories": len(advisories),
            "total_advisories": sum(len(v) for v in advisories.values()), "errors": errors}

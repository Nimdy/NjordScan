"""Dependency detector: known-vulnerable versions and typosquats.

V1 of NjordScan claimed to check dependencies but never actually consulted a
vulnerability database. This detector ships a small, curated advisory DB
(``njordscan/data/advisories/known_vulns.json``) of real, well-known npm
advisories and checks each declared dependency against it.

Two checks:

1. **Known vulnerability** — parse the version declared in ``package.json``
   (stripping ``^``/``~``/range operators down to a concrete version), then test
   it against the ``vulnerable_range`` of every advisory for that package using
   :mod:`packaging.specifiers`. A hit produces ``deps.known-vulnerability`` with
   the advisory id, the vulnerable range, and the patched version in the message
   and ``metadata``.

2. **Typosquatting** — compare each dependency name against a list of the most
   popular npm packages. A name that is one edit away from a popular package (or
   a known confusable like ``loadsh``) but not exactly it produces
   ``deps.typosquat``. We are deliberately conservative (short names, scoped
   names, and known-good packages are excluded) to keep false positives near
   zero.

Robustness: :meth:`scan` never raises. All parsing/IO is wrapped, the advisory
DB is loaded once and cached, and the (cheap, CPU-bound) work runs in a worker
thread via ``asyncio.to_thread`` so the event loop is not blocked.
"""

from __future__ import annotations

import asyncio
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.finding import Finding
from ..core.project import Project
from ..core.severity import Severity
from .base import Detector

# Location of the shipped advisory database (packaged as data, see pyproject).
_ADVISORY_PATH = Path(__file__).resolve().parent.parent / "data" / "advisories" / "known_vulns.json"

# Top ~40 popular npm package names used as the typosquat reference set.
# Kept lowercase; exact matches are obviously fine and never flagged.
_POPULAR_PACKAGES: Tuple[str, ...] = (
    "react", "react-dom", "next", "vite", "vue", "svelte", "angular",
    "lodash", "underscore", "moment", "dayjs", "axios", "express", "koa",
    "fastify", "webpack", "rollup", "esbuild", "babel", "typescript",
    "eslint", "prettier", "jest", "mocha", "chalk", "commander", "yargs",
    "dotenv", "uuid", "nanoid", "zod", "yup", "redux", "mobx", "tailwindcss",
    "postcss", "graphql", "prisma", "mongoose", "sequelize", "jsonwebtoken",
    "bcrypt", "passport", "cors", "request", "node-fetch", "socket.io",
)

# Names that are legitimately close to a popular package but are themselves
# real, popular packages — never flag these as typosquats.
_KNOWN_GOOD: frozenset[str] = frozenset({
    "preact", "react-dom", "react-is", "reactstrap", "react-router",
    "vuex", "vite-plugin-pwa", "next-auth", "next-seo", "lodash-es",
    "lodash.merge", "lodash.get", "expressjs", "koa-router", "vue-router",
    "babel-core", "core-js", "rxjs", "zone.js", "immer", "axios-retry",
})

# A handful of well-known confusables that edit-distance alone may rank as
# distance > 1 or that we want to flag with extra certainty.
_KNOWN_CONFUSABLES: Dict[str, str] = {
    "loadsh": "lodash",
    "lodahs": "lodash",
    "reactt": "react",
    "raect": "react",
    "expres": "express",
    "expresss": "express",
    "axioss": "axios",
    "momet": "moment",
    "webpcak": "webpack",
    "typscript": "typescript",
    "crossenv": "cross-env",
    "mongose": "mongoose",
    "jsonwebtokens": "jsonwebtoken",
    "nextjs": "next",
    "vuejs": "vue",
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Matches the first "x.y.z"-ish version token in a declared range string.
_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-]+)?")


class DependenciesDetector(Detector):
    id = "dependencies"
    name = "Vulnerable & typosquatted dependencies"
    kind = "static"

    def applies(self, project: Project) -> bool:
        return bool(project.dependencies) or (project.root / "package.json").exists()

    async def scan(self, project: Project) -> List[Finding]:
        try:
            return await asyncio.to_thread(self._scan_sync, project)
        except Exception:  # noqa: BLE001 — a detector must never crash the scan
            return []

    # -- synchronous core (runs in a worker thread) -------------------------

    def _scan_sync(self, project: Project) -> List[Finding]:
        findings: List[Finding] = []
        try:
            deps = project.dependencies or {}
        except Exception:  # noqa: BLE001
            deps = {}

        advisories = _load_advisories()
        pkg_line_index = self._build_pkg_line_index(project)
        try:
            from ..core.usage import UsageIndex
            usage = UsageIndex(project)
        except Exception:  # noqa: BLE001 — usage analysis is best-effort
            usage = None

        for name, declared in deps.items():
            try:
                line = pkg_line_index.get(name, 1)
                findings.extend(
                    self._check_known_vuln(name, str(declared), line, advisories, usage)
                )
                typo = self._check_typosquat(name, line)
                if typo is not None:
                    findings.append(typo)
            except Exception:  # noqa: BLE001 — isolate per-dependency failures
                continue
        return findings

    # -- known vulnerability check ------------------------------------------

    def _check_known_vuln(
        self,
        name: str,
        declared: str,
        line: int,
        advisories: Dict[str, List[Dict[str, Any]]],
        usage=None,
    ) -> List[Finding]:
        entries = advisories.get(name)
        if not entries:
            return []

        version = _coerce_version(declared)
        if version is None:
            # No concrete version to test (e.g. "latest", git/file/workspace URL).
            return []

        out: List[Finding] = []
        for adv in entries:
            try:
                vuln_range = str(adv.get("vulnerable_range", "")).strip()
                if not vuln_range or not _in_range(version, vuln_range):
                    continue
            except Exception:  # noqa: BLE001 — a malformed advisory must not break others
                continue

            adv_id = str(adv.get("id") or adv.get("ghsa") or "advisory")
            patched = str(adv.get("patched") or "the latest version")
            summary = str(adv.get("summary") or "").strip()
            severity = _SEVERITY_MAP.get(str(adv.get("severity", "")).lower())

            # Exploit intelligence: actively-exploited CVEs (CISA KEV) jump to the
            # top of the queue regardless of the advisory's nominal severity.
            from ..core.exploit import epss_for, is_kev
            kev = is_kev(adv_id)
            epss = epss_for(adv_id)
            prefix = "🚨 ACTIVELY EXPLOITED (CISA KEV) — patch immediately. " if kev else ""
            if kev:
                severity = Severity.CRITICAL

            # VEX / reachability: do you actually call the vulnerable code?
            vex_state, vex_just, reachable, reach_note = _vex(name, adv, usage)
            if reachable is False and not kev:
                # vulnerable code isn't reachable from your app -> downgrade noise
                severity = Severity.LOW if severity and severity.rank > Severity.LOW.rank else severity

            message = (
                f"{prefix}{name}@{declared} is affected by {adv_id} "
                f"(vulnerable {vuln_range}). Upgrade to {patched} or later."
            )
            if epss is not None:
                message += f" (EPSS {epss:.0%} 30-day exploit probability)"
            if reach_note:
                message += f" {reach_note}"
            if summary:
                message += f" {summary}"

            out.append(Finding(
                rule_id="deps.known-vulnerability",
                reachable=reachable,
                # Include the advisory id in the snippet so two distinct
                # advisories for the same package on the same line don't collapse
                # to one fingerprint during dedup (fingerprint = rule|file|line|snippet).
                code_snippet=f'"{name}": "{declared}"  // {adv_id}',
                file="package.json",
                line=line,
                detector=self.id,
                confidence="high",
                message=message,
                severity=severity,
                metadata={
                    "package": name,
                    "declared": declared,
                    "resolved_version": str(version),
                    "advisory_id": adv_id,
                    "ghsa": adv.get("ghsa"),
                    "vulnerable_range": vuln_range,
                    "patched": patched,
                    "advisory_severity": adv.get("severity"),
                    "cwe": adv.get("cwe"),
                    "references": adv.get("references", []),
                    "summary": summary,
                    "cisa_kev": kev,
                    "epss": epss,
                    "vex_state": vex_state,
                    "vex_justification": vex_just,
                    "vulnerable_symbols": adv.get("vulnerable_symbols", []),
                },
            ))
        return out

    # -- typosquat check -----------------------------------------------------

    def _check_typosquat(self, name: str, line: int) -> Optional[Finding]:
        target = self._typosquat_target(name)
        if target is None:
            return None
        return Finding(
            rule_id="deps.typosquat",
            file="package.json",
            line=line,
            code_snippet=f'"{name}"',
            detector=self.id,
            confidence="medium",
            message=(
                f"Dependency '{name}' is suspiciously similar to the popular "
                f"package '{target}'. Confirm you did not mistype the name "
                "(typosquatting installs an attacker's package)."
            ),
            metadata={"package": name, "looks_like": target},
        )

    def _typosquat_target(self, name: str) -> Optional[str]:
        raw = name.strip()
        lower = raw.lower()

        # Scoped packages (@scope/name): only inspect the name part, and only
        # for very well-known scopes is mimicry meaningful; skip to stay precise.
        if raw.startswith("@"):
            return None

        # Exact match or otherwise known-good package: never a typosquat.
        if lower in _POPULAR_PACKAGES or lower in _KNOWN_GOOD:
            return None

        # Explicit confusables we are confident about.
        confusable = _KNOWN_CONFUSABLES.get(lower)
        if confusable is not None and confusable != lower:
            return confusable

        # Be conservative: very short names produce noisy edit-distance hits.
        if len(lower) < 4:
            return None

        # Find the closest popular package by edit distance.
        best: Optional[str] = None
        best_dist = 99
        for popular in _POPULAR_PACKAGES:
            # Only compare names of similar length; an edit distance of 1 between
            # very different-length strings is impossible anyway.
            if abs(len(popular) - len(lower)) > 1:
                continue
            if popular == lower:
                return None
            dist = _edit_distance(lower, popular, max_dist=1)
            if dist < best_dist:
                best_dist = dist
                best = popular

        if best is not None and best_dist == 1 and len(best) >= 4:
            return best
        return None

    # -- helpers -------------------------------------------------------------

    def _build_pkg_line_index(self, project: Project) -> Dict[str, int]:
        """Map dependency name -> line number in package.json for nicer reports."""
        index: Dict[str, int] = {}
        try:
            pkg_path = project.root / "package.json"
            if not pkg_path.exists():
                return index
            text = project.read_text(pkg_path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                m = re.match(r'\s*"([^"]+)"\s*:', line)
                if m:
                    # First occurrence wins (declaration in deps/devDeps block).
                    index.setdefault(m.group(1), line_no)
        except Exception:  # noqa: BLE001
            return {}
        return index


# -- module-level pure helpers ----------------------------------------------


def _vex(name: str, adv: Dict[str, Any], usage) -> tuple:
    """Return (vex_state, justification, reachable, human_note) for an advisory.

    Uses dependency usage analysis to decide whether the vulnerable code is actually
    reachable from the app — the real VEX signal.
    """
    if usage is None:
        return "in_triage", "", None, ""
    symbols = set(adv.get("vulnerable_symbols", []) or [])
    used = usage.uses_symbol(name, symbols)
    if used is None:
        return ("not_affected", "code_not_present", False,
                f"✅ Not reachable: `{name}` isn't imported in your code (likely a transitive dependency).")
    if used is False and symbols:
        sym = ", ".join(sorted(symbols))
        return ("not_affected", "vulnerable_code_not_in_execute_path", False,
                f"✅ Lower priority: you import `{name}` but never call the vulnerable `{sym}`.")
    if symbols and used is True:
        sym = ", ".join(sorted(symbols))
        return ("exploitable", "", True,
                f"🎯 Reachable: your code calls the vulnerable `{sym}` from `{name}`.")
    # imported, no symbol-level info available
    return ("affected", "", True, f"🎯 `{name}` is imported and used in your code.")


def _read_advisory_file(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    advisories = data.get("advisories") if isinstance(data, dict) else None
    if not isinstance(advisories, dict):
        return {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for pkg, entries in advisories.items():
        if isinstance(entries, list):
            out[str(pkg)] = [e for e in entries if isinstance(e, dict)]
    return out


@lru_cache(maxsize=1)
def _load_advisories() -> Dict[str, List[Dict[str, Any]]]:
    """Merge the shipped advisory DB with any user cache from ``njordscan update``.

    User-refreshed advisories (``~/.njordscan/advisories.json``) are added on top
    of the shipped seed; entries are de-duplicated per package by advisory id.
    """
    merged: Dict[str, List[Dict[str, Any]]] = {}
    sources = [_ADVISORY_PATH]
    try:
        from ..core.paths import user_advisories_path
        sources.append(user_advisories_path())
    except Exception:  # noqa: BLE001
        pass

    for path in sources:
        for pkg, entries in _read_advisory_file(path).items():
            bucket = merged.setdefault(pkg, [])
            seen = {str(e.get("id") or e.get("ghsa")) for e in bucket}
            for e in entries:
                key = str(e.get("id") or e.get("ghsa"))
                if key not in seen:
                    bucket.append(e)
                    seen.add(key)
    return merged


def _coerce_version(declared: str):
    """Extract a concrete, comparable version from a declared npm range.

    Returns a ``packaging.version.Version`` or ``None`` if no concrete version
    can be derived (``*``, ``latest``, git/file/workspace URLs, etc.).
    """
    if not declared:
        return None
    spec = declared.strip()

    # Things with no testable concrete version.
    low = spec.lower()
    if low in ("*", "latest", "") or low.startswith((
        "git", "http", "file:", "link:", "workspace:", "npm:", "github:",
    )) or "/" in spec.split("#")[0] and not spec[0].isdigit():
        # npm: aliases and url/path specs — skip (can't resolve offline reliably).
        if not _VERSION_TOKEN.search(spec):
            return None

    m = _VERSION_TOKEN.search(spec)
    if not m:
        return None
    token = m.group(0)
    # Pad to at least major.minor.patch so Version compares sanely (4 -> 4.0.0).
    parts = token.split("+")[0].split("-")[0].split(".")
    while len(parts) < 3:
        parts.append("0")
    base = ".".join(parts[:3])
    suffix = token[len(token.split("+")[0].split("-")[0]):]  # keep -pre / +build
    candidate = base + suffix
    try:
        from packaging.version import Version
        return Version(candidate)
    except Exception:  # noqa: BLE001 — invalid version token
        try:
            from packaging.version import Version
            return Version(base)
        except Exception:  # noqa: BLE001
            return None


def _in_range(version, vulnerable_range: str) -> bool:
    """True if ``version`` satisfies the advisory's vulnerable specifier set."""
    try:
        from packaging.specifiers import SpecifierSet
        # Accept both comma-separated ("<2.0.0,>=1.0.0") and the single-op forms.
        spec = SpecifierSet(vulnerable_range)
        return version in spec or spec.contains(version, prereleases=True)
    except Exception:  # noqa: BLE001 — malformed range never matches
        return False


def _edit_distance(a: str, b: str, max_dist: int = 1) -> int:
    """Levenshtein distance with early exit once it exceeds ``max_dist``.

    Returns ``max_dist + 1`` as soon as the distance is known to exceed the
    threshold, so we never do more work than needed for the conservative
    typosquat check.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1

    previous = list(range(lb + 1))
    for i in range(1, la + 1):
        current = [i] + [0] * lb
        row_min = current[0]
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            current[j] = min(
                previous[j] + 1,       # deletion
                current[j - 1] + 1,    # insertion
                previous[j - 1] + cost  # substitution
            )
            if current[j] < row_min:
                row_min = current[j]
        if row_min > max_dist:
            return max_dist + 1
        previous = current
    return previous[lb]

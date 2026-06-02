"""Configuration detector — insecure framework/build configuration.

Catches misconfigurations that loosen safety across the whole app, the kind of
thing that is easy to ship by accident and hard to notice in review:

  - next.config: ``typescript.ignoreBuildErrors`` / ``eslint.ignoreDuringBuilds``
    (which hide real bugs in production builds) and overly broad image
    ``domains`` / ``remotePatterns`` (which let attackers proxy arbitrary content
    through your domain).
  - Disabled TLS verification anywhere: ``NODE_TLS_REJECT_UNAUTHORIZED=0`` or
    ``rejectUnauthorized: false`` (man-in-the-middle risk).
  - A Next.js app whose next.config defines no security headers via ``headers()``
    (advisory / low confidence — security headers may be set elsewhere).

Config files are NEVER executed; they are parsed with conservative regex
heuristics. ``scan()`` never raises — every file is read/parsed defensively and
partial results are returned on error.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import List, Optional, Tuple

from ..core.finding import Finding
from ..core.project import Project
from ..core.severity import Severity
from .base import Detector

# Next.js config filenames, in the order Next.js itself resolves them.
_NEXT_CONFIG_NAMES = ("next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs")
# Vite config filenames.
_VITE_CONFIG_NAMES = (
    "vite.config.js", "vite.config.ts", "vite.config.mjs", "vite.config.cjs", "vite.config.mts",
)

# Security headers we consider "present enough" to satisfy the advisory check.
_SECURITY_HEADER_NAMES = (
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
)

# --- next.config dangerous-option patterns -------------------------------------
# Each: (regex, the option label used in the message). Whitespace/newline tolerant
# so `typescript: {\n ignoreBuildErrors: true\n }` matches as well as inline.
_IGNORE_BUILD_ERRORS = re.compile(r"ignoreBuildErrors\s*:\s*true\b", re.I)
_IGNORE_DURING_BUILDS = re.compile(r"ignoreDuringBuilds\s*:\s*true\b", re.I)

# images.domains: [...] — capture the array body to look for a bare '*'.
_IMAGES_DOMAINS = re.compile(r"domains\s*:\s*\[(?P<body>[^\]]*)\]", re.I | re.S)
# A wildcard host inside an array literal: '*' or "*" (optionally as **.foo too).
_WILDCARD_DOMAIN = re.compile(r"""['"]\s*\*[^'"]*['"]""")
# remotePatterns hostname that is a bare wildcard.
_REMOTE_PATTERNS_BLOCK = re.compile(r"remotePatterns\s*:\s*\[", re.I)
_WILDCARD_HOSTNAME = re.compile(r"""hostname\s*:\s*['"]\s*\*+\s*['"]""", re.I)

# headers() function declaration in a next.config (sync or async, various forms).
_HEADERS_FN = re.compile(
    r"""(?:async\s+)?      # optional async
        (?:function\s+)?    # `function headers(` form
        headers\s*         # the name
        (?:=\s*(?:async\s*)?)?  # `headers = async (` / `headers: async (`
        \(""",              # opening paren of the param list
    re.I | re.X,
)

# --- TLS verification disabling (anywhere) -------------------------------------
# NODE_TLS_REJECT_UNAUTHORIZED set to 0 / '0' (assignment or env-file or env mutation).
_TLS_REJECT_ENV = re.compile(
    r"""NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?""", re.I
)
# rejectUnauthorized: false (object option, e.g. https.Agent / tls.connect / axios).
_REJECT_UNAUTHORIZED_FALSE = re.compile(r"rejectUnauthorized\s*:\s*false\b", re.I)


class ConfigsDetector(Detector):
    """Flag insecure framework/build configuration."""

    id = "configs"
    name = "Insecure configuration"
    kind = "static"

    async def scan(self, project: Project) -> List[Finding]:
        try:
            return await asyncio.to_thread(self._scan, project)
        except Exception:  # noqa: BLE001 — a detector must never crash the scan
            return []

    # -- orchestration (runs off-thread) ------------------------------------

    def _scan(self, project: Project) -> List[Finding]:
        findings: List[Finding] = []

        next_config = self._find_config(project, _NEXT_CONFIG_NAMES)
        next_text = project.read_text(next_config) if next_config else ""

        # 1) next.config dangerous options
        if next_config is not None:
            try:
                findings.extend(self._scan_next_config(project, next_config, next_text))
            except Exception:  # noqa: BLE001
                pass

        # 2) disabled TLS verification (config files + all source files + env files)
        try:
            findings.extend(self._scan_tls(project, next_config, next_text))
        except Exception:  # noqa: BLE001
            pass

        # 3) missing security headers (Next.js only, advisory)
        try:
            mh = self._scan_missing_headers(project, next_config, next_text)
            if mh is not None:
                findings.append(mh)
        except Exception:  # noqa: BLE001
            pass

        return findings

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _find_config(project: Project, names: Tuple[str, ...]) -> Optional[Path]:
        try:
            return project.find_file(*names)
        except Exception:  # noqa: BLE001
            return None

    # -- 1) next.config dangerous options -----------------------------------

    def _scan_next_config(self, project: Project, path: Path, text: str) -> List[Finding]:
        if not text:
            return []
        rel = project.rel(path)
        out: List[Finding] = []

        for regex, option in (
            (_IGNORE_BUILD_ERRORS, "typescript.ignoreBuildErrors"),
            (_IGNORE_DURING_BUILDS, "eslint.ignoreDuringBuilds"),
        ):
            m = regex.search(text)
            if m:
                line = self._line_of(text, m.start())
                out.append(Finding(
                    rule_id="nextjs.dangerous-config",
                    file=rel,
                    line=line,
                    column=self._col_of(text, m.start()),
                    code_snippet=self._snippet(text, line),
                    detector=self.id,
                    confidence="high",
                    message=(
                        f"`{option}: true` disables a safety check, "
                        "letting type/lint errors ship to production."
                    ),
                ))

        # images.domains containing a wildcard
        for dm in _IMAGES_DOMAINS.finditer(text):
            if _WILDCARD_DOMAIN.search(dm.group("body")):
                line = self._line_of(text, dm.start())
                out.append(Finding(
                    rule_id="nextjs.dangerous-config",
                    file=rel,
                    line=line,
                    column=self._col_of(text, dm.start()),
                    code_snippet=self._snippet(text, line),
                    detector=self.id,
                    confidence="high",
                    message=(
                        "`images.domains` contains a wildcard '*' — any host can be "
                        "proxied through your Next.js image optimizer."
                    ),
                ))
                break  # one finding for the option is enough

        # remotePatterns with a wildcard hostname
        if _REMOTE_PATTERNS_BLOCK.search(text):
            hm = _WILDCARD_HOSTNAME.search(text)
            if hm:
                line = self._line_of(text, hm.start())
                out.append(Finding(
                    rule_id="nextjs.dangerous-config",
                    file=rel,
                    line=line,
                    column=self._col_of(text, hm.start()),
                    code_snippet=self._snippet(text, line),
                    detector=self.id,
                    confidence="high",
                    message=(
                        "`images.remotePatterns` uses a wildcard hostname — scope it "
                        "to hosts you control."
                    ),
                ))

        return out

    # -- 2) disabled TLS verification ---------------------------------------

    def _scan_tls(
        self, project: Project, next_config: Optional[Path], next_text: str
    ) -> List[Finding]:
        out: List[Finding] = []
        seen: set = set()

        for path, text in self._tls_targets(project, next_config, next_text):
            if not text:
                continue
            rel = project.rel(path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if len(line) > 2000:  # skip minified / data lines
                    continue
                match = None
                reason = ""
                m = _TLS_REJECT_ENV.search(line)
                if m:
                    match = m
                    reason = "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification"
                else:
                    m = _REJECT_UNAUTHORIZED_FALSE.search(line)
                    if m:
                        match = m
                        reason = "`rejectUnauthorized: false` disables TLS certificate verification"
                if match is None:
                    continue
                key = (rel, line_no, reason)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    rule_id="config.disabled-tls-verification",
                    file=rel,
                    line=line_no,
                    column=match.start() + 1,
                    code_snippet=line.strip(),
                    detector=self.id,
                    severity=Severity.HIGH,
                    confidence="high",
                    message=f"{reason} (man-in-the-middle risk).",
                ))
        return out

    def _tls_targets(
        self, project: Project, next_config: Optional[Path], next_text: str
    ):
        """Yield (path, text) pairs to scan for disabled TLS verification."""
        seen_paths: set = set()

        # config files first (and reuse the already-read next.config text)
        if next_config is not None:
            seen_paths.add(next_config)
            yield next_config, next_text
        vite_config = self._find_config(project, _VITE_CONFIG_NAMES)
        if vite_config is not None and vite_config not in seen_paths:
            seen_paths.add(vite_config)
            yield vite_config, project.read_text(vite_config)

        # normal source files
        for path in project.source_files:
            if path in seen_paths:
                continue
            seen_paths.add(path)
            yield path, project.read_text(path)

        # committed env files (where NODE_TLS_REJECT_UNAUTHORIZED is commonly set)
        for pattern in (".env", ".env.*", "*.env"):
            try:
                candidates = list(project.root.rglob(pattern))
            except OSError:
                continue
            for path in candidates:
                if path in seen_paths or not path.is_file():
                    continue
                if project.is_ignored(path):
                    continue
                try:
                    if path.stat().st_size > project.config.max_file_bytes:
                        continue
                except OSError:
                    continue
                seen_paths.add(path)
                yield path, project.read_text(path)

    # -- 3) missing security headers (advisory) -----------------------------

    def _scan_missing_headers(
        self, project: Project, next_config: Optional[Path], next_text: str
    ) -> Optional[Finding]:
        # Only meaningful when we have a next.config to analyze. Without one we
        # cannot tell whether headers are set elsewhere, so we stay silent to
        # avoid false positives (e.g. clean-app has `next` as a dep but no config).
        if next_config is None or not next_text:
            return None
        if project.framework != "nextjs":
            return None

        if self._defines_security_header(next_text):
            return None

        rel = project.rel(next_config)
        return Finding(
            rule_id="config.missing-security-headers",
            file=rel,
            line=1,
            detector=self.id,
            severity=Severity.MEDIUM,
            confidence="low",
            message=(
                "next.config defines no security headers (no `headers()` setting "
                "X-Frame-Options / Content-Security-Policy / Strict-Transport-Security). "
                "Add them for defense in depth, unless you set them in middleware."
            ),
        )

    @staticmethod
    def _defines_security_header(text: str) -> bool:
        """True if next.config has a headers() function AND names a security header."""
        if not _HEADERS_FN.search(text):
            return False
        lower = text.lower()
        return any(name in lower for name in _SECURITY_HEADER_NAMES)

    # -- small location helpers ---------------------------------------------

    @staticmethod
    def _col_of(text: str, index: int) -> int:
        """1-based column of character ``index`` within its line."""
        last_nl = text.rfind("\n", 0, index)
        return index - last_nl

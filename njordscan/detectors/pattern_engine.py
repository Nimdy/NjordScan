"""Data-driven pattern detector.

Most "is this risky shape present?" rules don't need a full AST — they need a
precise regex plus a little context. This detector loads rule *data* from
``njordscan/data/patterns/*.yaml`` so the rule library can grow without code
changes, while keeping false positives low via per-pattern filters:

  - ``languages`` / ``frameworks`` / ``paths`` — only run where relevant
  - ``requires_file`` / ``requires_line`` — extra regex that must ALSO match
  - ``exclude_line`` — voids a match (e.g. a known-safe shape)
  - ``multiline`` — match across the whole file instead of line-by-line

Every line can opt out with a trailing ``njordscan-ignore`` / ``nosec`` comment,
so a developer is never stuck fighting a false positive.

YAML schema (one list item per rule):

    - rule_id: react.unsafe-target-blank          # must exist in knowledge/rules.py
      pattern: 'target=["\\']_blank["\\']'         # required regex
      languages: [jsx, tsx]                        # optional; default = all code files
      frameworks: [react, nextjs]                  # optional; default = all
      paths: ["**/*.config.*"]                     # optional fnmatch globs
      requires_file: 'href='                       # optional regex anywhere in file
      requires_line: null                          # optional regex on the same line
      exclude_line: 'rel=["\\'][^"\\']*noopener'   # optional; voids the match
      multiline: false                             # optional; default false
      confidence: medium                           # optional; default medium
      severity: high                               # optional; overrides rule default
      message: "target=_blank without rel=noopener" # optional per-occurrence text
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Pattern, Set

import yaml

from ..core.finding import Finding
from ..core.project import Project
from ..core.severity import Severity
from .base import Detector

logger = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).resolve().parent.parent / "data" / "patterns"

_EXT_TO_LANG = {
    ".js": "js", ".mjs": "js", ".cjs": "js",
    ".jsx": "jsx", ".ts": "ts", ".tsx": "tsx",
}

# A line with one of these trailing markers is intentionally exempted by the dev.
_IGNORE_MARKER = re.compile(r"(njordscan-ignore|nosec|njord-ignore)\b", re.I)


@dataclass
class CompiledPattern:
    rule_id: str
    regex: Pattern[str]
    message: str
    confidence: str = "medium"
    severity: Optional[Severity] = None
    languages: Set[str] = field(default_factory=set)
    frameworks: Set[str] = field(default_factory=set)
    paths: List[str] = field(default_factory=list)
    requires_file: Optional[Pattern[str]] = None
    requires_line: Optional[Pattern[str]] = None
    exclude_line: Optional[Pattern[str]] = None
    exclude_window: Optional[Pattern[str]] = None   # void match if this appears within ±window lines
    exclude_window_lines: int = 4
    multiline: bool = False
    source_file: str = ""

    def applies_to(self, lang: str, framework: str, rel_path: str) -> bool:
        if self.languages and lang not in self.languages:
            return False
        if self.frameworks and framework not in self.frameworks and framework != "unknown":
            return False
        if self.paths and not any(fnmatch.fnmatch(rel_path, g) for g in self.paths):
            return False
        return True


class PatternEngine(Detector):
    id = "patterns"
    name = "Pattern rules"
    kind = "static"

    def __init__(self) -> None:
        self.patterns: List[CompiledPattern] = _load_patterns()

    async def scan(self, project: Project) -> List[Finding]:
        if not self.patterns:
            return []
        results = await asyncio.gather(
            *(asyncio.to_thread(self._scan_file, project, path) for path in project.source_files)
        )
        out: List[Finding] = []
        for chunk in results:
            out.extend(chunk)
        return out

    def _scan_file(self, project: Project, path: Path) -> List[Finding]:
        try:
            text = project.read_text(path)
            if not text:
                return []
            lang = _EXT_TO_LANG.get(path.suffix.lower(), "js")
            rel = project.rel(path)
            applicable = [p for p in self.patterns if p.applies_to(lang, project.framework, rel)]
            if not applicable:
                return []
            lines = text.splitlines()
            out: List[Finding] = []
            for pat in applicable:
                if pat.requires_file and not pat.requires_file.search(text):
                    continue
                if pat.multiline:
                    out.extend(self._match_multiline(pat, text, lines, rel))
                else:
                    out.extend(self._match_lines(pat, lines, rel))
            return out
        except Exception as exc:  # noqa: BLE001 — never let one file break the scan
            logger.debug("pattern scan failed for %s: %s", path, exc)
            return []

    def _match_lines(self, pat: CompiledPattern, lines: List[str], rel: str) -> List[Finding]:
        out: List[Finding] = []
        for i, line in enumerate(lines, start=1):
            if len(line) > 2000:
                continue
            m = pat.regex.search(line)
            if not m:
                continue
            if _IGNORE_MARKER.search(line):
                continue
            if pat.requires_line and not pat.requires_line.search(line):
                continue
            if pat.exclude_line and pat.exclude_line.search(line):
                continue
            if pat.exclude_window and self._window_excludes(pat, lines, i):
                continue
            out.append(self._finding(pat, rel, i, m.start() + 1, line.strip()))
        return out

    @staticmethod
    def _window_excludes(pat: CompiledPattern, lines: List[str], line_no: int) -> bool:
        """True if the exclude_window pattern appears within ±N lines (e.g. rel= on an
        adjacent line of a multi-line JSX element)."""
        lo = max(0, line_no - 1 - pat.exclude_window_lines)
        hi = min(len(lines), line_no + pat.exclude_window_lines)
        return any(pat.exclude_window.search(lines[j]) for j in range(lo, hi))

    def _match_multiline(self, pat: CompiledPattern, text: str, lines: List[str], rel: str) -> List[Finding]:
        out: List[Finding] = []
        for m in pat.regex.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = lines[line_no - 1] if 0 < line_no <= len(lines) else m.group(0)
            if _IGNORE_MARKER.search(line):
                continue
            if pat.exclude_line and pat.exclude_line.search(m.group(0)):
                continue
            snippet = m.group(0).strip()
            if len(snippet) > 200:
                snippet = line.strip()
            out.append(self._finding(pat, rel, line_no, m.start() - text.rfind("\n", 0, m.start()), snippet))
        return out

    def _finding(self, pat: CompiledPattern, rel: str, line: int, col: int, snippet: str) -> Finding:
        return Finding(
            rule_id=pat.rule_id,
            file=rel,
            line=line,
            column=max(col, 1),
            code_snippet=snippet,
            detector=self.id,
            confidence=pat.confidence,
            severity=pat.severity,
            message=pat.message,
            metadata={"pattern_source": pat.source_file},
        )


def _compile(entry: dict, source_file: str) -> Optional[CompiledPattern]:
    try:
        rule_id = entry["rule_id"]
        raw = entry["pattern"]
    except (KeyError, TypeError):
        logger.warning("pattern in %s missing rule_id/pattern: %r", source_file, entry)
        return None
    flags = re.IGNORECASE if entry.get("ignorecase", True) else 0
    try:
        regex = re.compile(raw, flags | (re.MULTILINE if entry.get("multiline") else 0))
        req_file = re.compile(entry["requires_file"], flags) if entry.get("requires_file") else None
        req_line = re.compile(entry["requires_line"], flags) if entry.get("requires_line") else None
        exc_line = re.compile(entry["exclude_line"], flags) if entry.get("exclude_line") else None
        exc_window = re.compile(entry["exclude_window"], flags) if entry.get("exclude_window") else None
    except re.error as exc:
        logger.warning("bad regex for %s in %s: %s", rule_id, source_file, exc)
        return None
    sev = entry.get("severity")
    return CompiledPattern(
        rule_id=rule_id,
        regex=regex,
        message=entry.get("message", ""),
        confidence=entry.get("confidence", "medium"),
        severity=Severity.from_str(sev) if sev else None,
        languages=set(entry.get("languages", []) or []),
        frameworks=set(entry.get("frameworks", []) or []),
        paths=list(entry.get("paths", []) or []),
        requires_file=req_file,
        requires_line=req_line,
        exclude_line=exc_line,
        exclude_window=exc_window,
        exclude_window_lines=int(entry.get("exclude_window_lines", 4)),
        multiline=bool(entry.get("multiline", False)),
        source_file=source_file,
    )


def _load_patterns(directory: Optional[Path] = None) -> List[CompiledPattern]:
    directory = directory or _PATTERNS_DIR
    patterns: List[CompiledPattern] = []
    if not directory.exists():
        return patterns
    for yaml_path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or []
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("could not load pattern file %s: %s", yaml_path, exc)
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            compiled = _compile(entry, yaml_path.name)
            if compiled:
                patterns.append(compiled)
    return patterns

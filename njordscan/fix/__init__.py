"""Safe autofix.

For a non-expert audience, a fix button is gold — but a *wrong* auto-edit destroys
trust instantly. So NjordScan only auto-applies fixes that are **provably safe and
additive** (they cannot change program behavior for the worse) and shows exactly
what changed. Everything else stays a documented manual fix in the report.

Currently auto-fixable:
  - ``react.unsafe-target-blank`` — add ``rel="noopener noreferrer"`` (purely additive)
  - committed env secrets — add ``.env*`` patterns to ``.gitignore`` (file hardening)

Use ``--fix --dry-run`` to preview a unified diff without writing anything.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..core.finding import Finding
from ..core.orchestrator import ScanResult
from ..core.project import Project


@dataclass
class AppliedFix:
    rule_id: str
    file: str
    line: int
    description: str


@dataclass
class FixReport:
    applied: List[AppliedFix] = field(default_factory=list)
    files_changed: List[str] = field(default_factory=list)
    diffs: Dict[str, str] = field(default_factory=dict)
    dry_run: bool = False
    fixable_rules_seen: int = 0

    @property
    def count(self) -> int:
        return len(self.applied)


# --- line-level fixers: (line) -> new_line or None if not safely fixable -------

def _fix_target_blank(line: str) -> Optional[str]:
    if re.search(r'\brel\s*=', line):  # already has a rel attribute — leave it
        return None
    new = re.sub(r'(target\s*=\s*["\']_blank["\'])', r'\1 rel="noopener noreferrer"', line, count=1)
    return new if new != line else None


_LINE_FIXERS: Dict[str, Callable[[str], Optional[str]]] = {
    "react.unsafe-target-blank": _fix_target_blank,
}


def apply_fixes(result: ScanResult, project: Project, *, dry_run: bool = False) -> FixReport:
    report = FixReport(dry_run=dry_run)

    # 1) line-level fixes, grouped by file so we read/write each file once
    by_file: Dict[str, List[Finding]] = {}
    for f in result.findings:
        if f.rule_id in _LINE_FIXERS:
            report.fixable_rules_seen += 1
            by_file.setdefault(f.file, []).append(f)

    for rel, findings in by_file.items():
        path = project.root / rel
        try:
            original = path.read_text(encoding="utf-8")
        except OSError:
            continue
        lines = original.splitlines(keepends=True)
        changed = False
        for f in findings:
            idx = f.line - 1
            if not (0 <= idx < len(lines)):
                continue
            fixer = _LINE_FIXERS[f.rule_id]
            newline = fixer(lines[idx].rstrip("\n"))
            if newline is None:
                continue
            eol = "\n" if lines[idx].endswith("\n") else ""
            lines[idx] = newline + eol
            changed = True
            report.applied.append(AppliedFix(f.rule_id, rel, f.line, "added rel=\"noopener noreferrer\""))
        if changed:
            updated = "".join(lines)
            report.files_changed.append(rel)
            report.diffs[rel] = _unified(original, updated, rel)
            if not dry_run:
                path.write_text(updated, encoding="utf-8")

    # 2) project-level: harden .gitignore if secrets were found in an env file
    env_secret = any(
        f.rule_id.startswith("secret.") and re.search(r"(^|/)\.env", f.file)
        for f in result.findings
    )
    if env_secret:
        fix = _harden_gitignore(project, dry_run)
        if fix:
            applied, diff = fix
            report.applied.append(applied)
            report.files_changed.append(applied.file)
            report.diffs[applied.file] = diff

    return report


_ENV_IGNORE_LINES = (".env", ".env.local", ".env.*.local")


def _harden_gitignore(project: Project, dry_run: bool) -> Optional[tuple[AppliedFix, str]]:
    gi = project.root / ".gitignore"
    original = gi.read_text(encoding="utf-8") if gi.exists() else ""
    existing = {ln.strip() for ln in original.splitlines()}
    # If a broad env glob is already present, we're covered.
    if any(p in existing for p in (".env*", "*.env", ".env")) and ".env" in existing:
        return None
    missing = [p for p in _ENV_IGNORE_LINES if p not in existing]
    if not missing:
        return None
    block = ("\n" if original and not original.endswith("\n") else "") + \
            "\n# Added by njordscan --fix: never commit env files with secrets\n" + \
            "\n".join(missing) + "\n"
    updated = original + block
    if not dry_run:
        gi.write_text(updated, encoding="utf-8")
    return (
        AppliedFix("secret.generic", ".gitignore", 0, f"added {', '.join(missing)} to .gitignore"),
        _unified(original, updated, ".gitignore"),
    )


def _unified(before: str, after: str, name: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{name}", tofile=f"b/{name}",
    ))

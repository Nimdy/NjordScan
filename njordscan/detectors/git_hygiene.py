"""Git-hygiene detector.

Catches the single most common way beginners leak secrets: a ``.env`` file that
is either tracked by git or not covered by ``.gitignore``. Runs only inside a git
repository. Uses ``git`` when available for an authoritative answer, with a
``.gitignore`` parse as a fallback so it works without the git binary.
"""

from __future__ import annotations

import asyncio
import fnmatch
import subprocess
from pathlib import Path
from typing import List, Optional, Set

from ..core.finding import Finding
from ..core.project import Project
from .base import Detector

# Env files worth protecting. .env.example / .env.sample are meant to be committed.
_ENV_GLOBS = (".env", ".env.*")
_SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")


class GitHygieneDetector(Detector):
    id = "git-hygiene"
    name = "Git hygiene"
    kind = "static"

    def applies(self, project: Project) -> bool:
        return (project.root / ".git").exists()

    async def scan(self, project: Project) -> List[Finding]:
        return await asyncio.to_thread(self._scan, project)

    def _scan(self, project: Project) -> List[Finding]:
        env_files = self._env_files(project)
        if not env_files:
            return []

        tracked = _git_tracked_files(project.root)
        gitignore_patterns = _read_gitignore(project.root)
        findings: List[Finding] = []

        for path in env_files:
            rel = project.rel(path)
            if tracked is not None and rel in tracked:
                findings.append(Finding(
                    rule_id="hardening.env-committed",
                    file=rel, line=1, detector=self.id, confidence="high",
                    message=f"{rel} is tracked by git — its secrets are in the repository.",
                ))
            elif not _ignored(rel, gitignore_patterns):
                findings.append(Finding(
                    rule_id="hardening.env-not-gitignored",
                    file=rel, line=1, detector=self.id, confidence="high",
                    message=f"{rel} is not in .gitignore — it will be committed on the next `git add`.",
                ))
        return findings

    def _env_files(self, project: Project) -> List[Path]:
        out: List[Path] = []
        for glob in _ENV_GLOBS:
            for path in project.root.glob(glob):  # root-level only; that's where env files live
                if not path.is_file():
                    continue
                if any(path.name.endswith(s) for s in _SAFE_ENV_SUFFIXES):
                    continue
                out.append(path)
        return out


def _git_tracked_files(root: Path) -> Optional[Set[str]]:
    """Set of git-tracked paths (relative, posix), or None if git is unavailable."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def _read_gitignore(root: Path) -> List[str]:
    gi = root / ".gitignore"
    if not gi.exists():
        return []
    try:
        return [
            ln.strip() for ln in gi.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    except OSError:
        return []


def _ignored(rel: str, patterns: List[str]) -> bool:
    name = rel.split("/")[-1]
    for pat in patterns:
        p = pat.rstrip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p.lstrip("/")):
            return True
    return False

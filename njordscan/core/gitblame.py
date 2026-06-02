"""Minimal ``git blame`` / ``git rev-list`` helpers for temporal analysis.

Used to date a pre-existing link in a kill chain: *which commit (and author) planted
this line, and was that before or after the change under review?* Pure subprocess,
no dependencies, and degrades to ``None`` whenever git is unavailable or the line
isn't committed yet (so a brand-new uncommitted line is never mis-attributed)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Set, Tuple

# git's sentinel sha for a line that is staged/working-tree but not yet committed.
_UNCOMMITTED = "0" * 40


def blame_line(root: Path, file: str, line: int) -> Optional[Tuple[str, str, int]]:
    """Return (short_sha, author, author_time_epoch) for ``file:line``, or None.

    None means: git unavailable, the path/line doesn't resolve, or the line isn't
    committed (so it has no birthday yet — the caller treats it as brand-new)."""
    if line < 1:
        return None
    args = ["git", "-C", str(root), "blame", "--porcelain",
            "-L", f"{line},{line}", "--", file]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    lines = proc.stdout.splitlines()
    sha = lines[0].split(" ", 1)[0] if lines else ""
    if not sha or sha == _UNCOMMITTED:
        return None
    author = ""
    epoch = 0
    for ln in lines[1:]:
        if ln.startswith("author "):
            author = ln[len("author "):].strip()
        elif ln.startswith("author-time "):
            try:
                epoch = int(ln[len("author-time "):].strip())
            except ValueError:
                epoch = 0
        elif ln.startswith("\t"):  # the code line — porcelain header is done
            break
    return (sha[:12], author or "unknown", epoch)


def commits_in_range(root: Path, base_ref: str) -> Set[str]:
    """The set of commit shas in ``base_ref..HEAD`` (the changes under review).

    Used as a self-correcting guard: if a line we thought was pre-existing was last
    touched by a commit INSIDE this range (e.g. a reformat/move), it is actually part
    of the change and must not be attributed to an earlier author."""
    if not base_ref:
        return set()
    args = ["git", "-C", str(root), "rev-list", f"{base_ref}..HEAD"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return set()
    if proc.returncode != 0:
        return set()
    out: Set[str] = set()
    for sha in proc.stdout.split():
        out.add(sha)
        out.add(sha[:12])
    return out

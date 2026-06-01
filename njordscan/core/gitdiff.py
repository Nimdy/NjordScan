"""Map the lines changed vs a git ref, for ``--diff`` / PR mode.

Lets a scan report only issues on code you actually touched — fast feedback on a
PR, and a gentle way to adopt NjordScan without fixing the whole backlog at once.
Pairs with ``--fail-on`` so CI fails only on issues the change introduced.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, Optional, Set

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(root: Path, ref: str) -> Optional[Dict[str, Set[int]]]:
    """Return {relative_posix_path: {changed new-file line numbers}}.

    ``ref`` of "HEAD" compares the working tree (staged + unstaged) to the last
    commit; any other ref compares that ref to the working tree. Returns None if
    git is unavailable or the diff fails (caller should then skip diff filtering).
    """
    args = ["git", "-C", str(root), "diff", "--unified=0", "--no-color", "--no-ext-diff"]
    args += [ref] if ref else ["HEAD"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode not in (0, 1):  # 0/1 are normal for diff; other = error
        return None

    result: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:].strip()
            result.setdefault(current, set())
        elif line.startswith("+++ "):  # /dev/null (deletion)
            current = None
        elif current is not None and line.startswith("@@"):
            m = _HUNK.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            for ln in range(start, start + max(count, 1)):
                result[current].add(ln)
    return result


def in_diff(changed: Dict[str, Set[int]], file: str, line: int) -> bool:
    """Whether a finding at file:line falls within the changed set.

    File-level findings (line 0) count if the file changed at all.
    """
    lines = changed.get(file)
    if lines is None:
        return False
    if line <= 0:
        return True
    return line in lines

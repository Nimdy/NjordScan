"""--diff / PR mode: only report issues on changed lines."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from njordscan.core.gitdiff import changed_lines, in_diff

from conftest import CLEAN_APP

_HAS_GIT = shutil.which("git") is not None
pytestmark = pytest.mark.skipif(not _HAS_GIT, reason="git not installed")


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _init_repo(tmp_path):
    shutil.copytree(CLEAN_APP, tmp_path / "app")
    repo = tmp_path / "app"
    _git(repo, "init")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init")
    return repo


def test_changed_lines_detects_new_lines(tmp_path):
    repo = _init_repo(tmp_path)
    target = repo / "pages" / "index.jsx"
    target.write_text(target.read_text() + "\nconst x = 1;\nconst y = 2;\n")
    changed = changed_lines(repo, "HEAD")
    assert changed is not None
    assert "pages/index.jsx" in changed
    assert changed["pages/index.jsx"], "expected at least one changed line"


def test_in_diff_matching():
    changed = {"a.js": {5, 6, 7}}
    assert in_diff(changed, "a.js", 6)
    assert not in_diff(changed, "a.js", 99)
    assert not in_diff(changed, "other.js", 6)
    assert in_diff(changed, "a.js", 0)  # file-level finding counts if file changed


def test_changed_lines_unknown_ref_returns_data_or_none(tmp_path):
    repo = _init_repo(tmp_path)
    # a nonexistent ref should fail gracefully (None), not raise
    assert changed_lines(repo, "no-such-ref-xyz") is None

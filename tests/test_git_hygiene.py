"""Git-hygiene detector: committed / un-ignored .env files."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from conftest import rule_ids, scan

pytestmark = pytest.mark.asyncio

_HAS_GIT = shutil.which("git") is not None
skip_no_git = pytest.mark.skipif(not _HAS_GIT, reason="git not installed")


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@skip_no_git
async def test_env_not_gitignored_is_flagged(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost:5432/dev\n")
    (tmp_path / "package.json").write_text('{"name":"t"}')
    result = await scan(tmp_path, only_detectors=["git-hygiene"])
    assert "hardening.env-not-gitignored" in rule_ids(result.findings)


@skip_no_git
async def test_committed_env_is_critical(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost:5432/dev\n")
    _git(tmp_path, "add", ".env")
    _git(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x")
    result = await scan(tmp_path, only_detectors=["git-hygiene"])
    ids = rule_ids(result.findings)
    assert "hardening.env-committed" in ids


@skip_no_git
async def test_gitignored_env_is_silent(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost:5432/dev\n")
    (tmp_path / ".gitignore").write_text(".env\n")
    result = await scan(tmp_path, only_detectors=["git-hygiene"])
    assert result.total == 0


@skip_no_git
async def test_env_example_is_never_flagged(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".env.example").write_text("API_KEY=your-key-here\n")
    result = await scan(tmp_path, only_detectors=["git-hygiene"])
    assert result.total == 0

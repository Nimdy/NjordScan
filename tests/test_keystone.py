"""Keystone Commit — the change that armed a pre-existing kill chain.

Builds real throwaway git repos and proves the zero-LLM verdict: a chain that exists
AFTER but not BEFORE, with one in-diff link and one pre-existing link (dated by blame),
is flagged; a self-contained new chain or a no-op diff is not.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from njordscan.analysis import keystone
from conftest import scan

pytestmark = pytest.mark.asyncio

_PATH = os.environ.get("PATH", "/usr/bin:/bin")


def _git(repo, *args, author=None):
    env = None
    if author:
        name, email = author
        env = {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
               "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email,
               "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(repo), "PATH": _PATH}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def _init(repo):
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "commit.gpgsign", "false")


def _commit(repo, msg, author):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg, author=author)


# A route that already has a SQL-injection sink (the pre-existing link).
_ROUTE_SAFE = """\
import { db } from "@/lib/db";
export async function GET(req) {
  const url = new URL(req.url);
  const q = url.searchParams.get("q");
  const rows = await db.query(`SELECT * FROM products WHERE name = '${q}'`);
  return Response.json(rows);
}
"""
# The same route after a later commit stubs the auth guard (the keystone link).
_ROUTE_ARMED = "const isAuthenticated = (req) => true;\n" + _ROUTE_SAFE


def _scaffold(repo):
    (repo / "app" / "api" / "search").mkdir(parents=True, exist_ok=True)
    (repo / "package.json").write_text('{"name":"a","dependencies":{"next":"14.0.0"}}')
    (repo / "next.config.js").write_text("module.exports = {}\n")


async def test_keystone_flags_the_commit_that_completes_a_chain(tmp_path):
    repo = tmp_path / "repo"
    _init(repo)
    _scaffold(repo)
    route = repo / "app" / "api" / "search" / "route.ts"
    route.write_text(_ROUTE_SAFE)
    _commit(repo, "add search route with raw query", author=("Alice", "alice@x.test"))
    # a later commit by Bob stubs the auth guard — the keystone link
    route.write_text(_ROUTE_ARMED)
    _commit(repo, "temporarily disable auth guard", author=("Bob", "bob@x.test"))

    result = await scan(repo)
    ks = keystone(repo, "HEAD~1", result.attack_paths)
    assert ks, "the auth-stub commit should be flagged as a keystone"
    path = ks[0]
    provs = {s.provenance for s in path.steps}
    assert "newly-introduced" in provs and "pre-existing" in provs
    # the pre-existing SQLi link is attributed to Alice's earlier commit
    pre = [s for s in path.steps if s.provenance == "pre-existing"]
    assert any(s.born_author == "Alice" for s in pre)
    assert "Alice" in path.assemblers


async def test_self_contained_new_chain_is_not_a_keystone(tmp_path):
    # a commit that adds the WHOLE chain at once has no pre-existing link
    repo = tmp_path / "repo"
    _init(repo)
    _scaffold(repo)
    (repo / "README.md").write_text("# app\n")
    _commit(repo, "init", author=("Alice", "alice@x.test"))
    (repo / "app" / "api" / "search" / "route.ts").write_text(_ROUTE_ARMED)  # entire chain new
    _commit(repo, "add route", author=("Bob", "bob@x.test"))

    result = await scan(repo)
    ks = keystone(repo, "HEAD~1", result.attack_paths)
    assert all(any(s.provenance == "pre-existing" for s in k.steps) is False for k in ks) or ks == []
    assert not any(k.path.kind == "unauth-exec" for k in ks)


async def test_noop_diff_yields_no_keystone(tmp_path):
    repo = tmp_path / "repo"
    _init(repo)
    _scaffold(repo)
    (repo / "app" / "api" / "search" / "route.ts").write_text(_ROUTE_ARMED)
    _commit(repo, "c1", author=("Alice", "alice@x.test"))
    # a comment-only second commit changes no findings
    (repo / "README.md").write_text("# docs only\n")
    _commit(repo, "docs", author=("Bob", "bob@x.test"))

    result = await scan(repo)
    assert keystone(repo, "HEAD~1", result.attack_paths) == []


async def test_deterministic_and_safe_without_git(tmp_path):
    # not a git repo → returns [] gracefully, never raises
    (tmp_path / "x.ts").write_text("const x = 1;\n")
    assert keystone(tmp_path, "HEAD", []) == []
    assert keystone(tmp_path, "", []) == []

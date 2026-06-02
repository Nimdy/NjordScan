"""SQL-injection by data flow + idiomatic App Router sources + auth-bypass precision.

These lock in the 'fires on real-world idiomatic Next.js' improvements: user input
reaching a database query is caught by taint (not just regex), the canonical
`new URL(req.url).searchParams.get()` source resolves, parameterized queries are NOT
flagged, and the auth-guard-stub pattern matches `const x = () => true` shapes while
ignoring conditional returns.
"""

from __future__ import annotations

import pytest

from conftest import scan

pytestmark = pytest.mark.asyncio


def _app(tmp_path, route_src: str) -> object:
    (tmp_path / "app" / "api" / "x").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "api" / "x" / "route.ts").write_text(route_src)
    (tmp_path / "package.json").write_text('{"name":"a","dependencies":{"next":"14.0.0"}}')
    return tmp_path


async def _taint_rule_lines(tmp_path, rule_id):
    r = await scan(tmp_path, only_detectors=["taint"])
    return sorted(f.line for f in r.findings if f.rule_id == rule_id)


async def test_tainted_query_template_and_concat_and_prisma_unsafe(tmp_path):
    app = _app(tmp_path, """
import { db } from "@/lib/db";
import { prisma } from "@/lib/prisma";
export async function GET(req) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const a = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  const b = await db.execute("SELECT * FROM t WHERE n = '" + id + "'");
  const c = await prisma.$queryRawUnsafe(`SELECT ${id}`);
  return Response.json({ a, b, c });
}
""".lstrip())
    lines = await _taint_rule_lines(app, "sqli.tainted-query")
    # the three dangerous calls (lines 6,7,8 of the written file)
    assert len(lines) == 3


async def test_parameterized_and_safe_prisma_and_nondb_not_flagged(tmp_path):
    app = _app(tmp_path, """
import { db } from "@/lib/db";
import { prisma } from "@/lib/prisma";
export async function GET(req) {
  const id = new URL(req.url).searchParams.get("id");
  const a = await db.query("SELECT * FROM users WHERE id = ?", [id]);  // parameterized
  const b = await prisma.$queryRaw`SELECT ${id}`;                      // safe tagged template
  const c = queryClient.query(`anything ${id}`);                       // non-DB receiver
  return Response.json({ a, b, c });
}
""".lstrip())
    assert await _taint_rule_lines(app, "sqli.tainted-query") == []


async def test_searchparams_source_resolves_through_url_object(tmp_path):
    # the canonical App Router shape: new URL(req.url).searchParams.get(...)
    app = _app(tmp_path, """
import { db } from "@/lib/db";
export async function GET(req) {
  const q = new URL(req.url).searchParams.get("q");
  const rows = await db.query(`SELECT * FROM p WHERE name = '${q}'`);
  return Response.json(rows);
}
""".lstrip())
    r = await scan(app, only_detectors=["taint"])
    hits = [f for f in r.findings if f.rule_id == "sqli.tainted-query"]
    assert len(hits) == 1
    assert any("searchParams" in s.label for s in hits[0].taint_flow)  # source named


async def test_auth_guard_stub_pattern_matches_idiomatic_shapes(tmp_path):
    (tmp_path / "auth.ts").write_text("""
const isAuthenticated = (req) => true;
export const isLoggedIn = () => true;
const requireAuth = async (req) => true;
const canActivate = req => true;
const guard = { checkAuth: () => true };
const isAuthorized = () => true && realCheck();
const isAdmin = user.role === "admin";
""".lstrip())
    (tmp_path / "package.json").write_text('{"name":"a"}')
    r = await scan(tmp_path, only_detectors=["patterns"])
    lines = sorted(f.line for f in r.findings if f.rule_id == "auth.middleware-bypass")
    assert lines == [1, 2, 3, 4, 5]   # not the conditional (6) or the comparison (7)


async def test_flagship_unauth_injection_chain_fires_on_idiomatic_code(tmp_path):
    src = """
import { db } from "@/lib/db";
const isAuthenticated = (req) => true;
export async function GET(req) {
  if (!isAuthenticated(req)) return new Response("no", { status: 401 });
  const q = new URL(req.url).searchParams.get("q");
  const rows = await db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);
  return Response.json(rows);
}
""".lstrip()
    app = _app(tmp_path, src)
    r = await scan(app)
    assert any(p.kind == "unauth-exec" for p in r.attack_paths), \
        "the unauthenticated-injection chain should fire on idiomatic App Router code"

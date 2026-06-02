"""SSRF precision: a same-origin (relative) fetch is not SSRF, a user-controlled
HOST is.

Found by dogfooding a real Next.js app: `fetch(`/api/...`)` with a request value in
the path/query was flagged as 'server-side fetch to a user-controlled URL (SSRF)' —
8 false HIGH findings on ordinary same-origin API calls. SSRF needs the *host* to be
attacker-influenced; relative and fixed-literal-host URLs are not SSRF no matter what
flows into the path or query. These lock the fix in both SSRF detectors (taint +
static) and guard against re-introducing a false negative on a real SSRF.
"""

from __future__ import annotations

import pytest

from conftest import scan

pytestmark = pytest.mark.asyncio


def _route(tmp_path, src: str):
    (tmp_path / "app" / "api" / "x").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "api" / "x" / "route.ts").write_text(src)
    (tmp_path / "package.json").write_text('{"name":"a","dependencies":{"next":"14.0.0"}}')
    return tmp_path


async def _ssrf_lines(tmp_path):
    r = await scan(tmp_path, only_detectors=["taint", "static"])
    return sorted(f.line for f in r.findings if f.rule_id == "ssrf.fetch")


async def test_same_origin_relative_fetch_is_not_ssrf(tmp_path):
    app = _route(tmp_path, """
export async function GET(req) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const params = url.searchParams;
  const a = await fetch(`/api/items/${id}`);            // relative path
  const b = await fetch(`/api/list?${params.toString()}`); // relative + query
  const c = await fetch(`https://api.stripe.com/v1/${id}`); // fixed literal host
  return Response.json({ a, b, c });
}
""")
    assert await _ssrf_lines(app) == []   # none of these are SSRF


async def test_user_controlled_host_is_still_flagged(tmp_path):
    app = _route(tmp_path, """
export async function GET(req) {
  const url = new URL(req.url);
  const host = url.searchParams.get("host");
  const target = url.searchParams.get("url");
  const a = await fetch(`https://${host}/data`);  // host from user input
  const b = await fetch(target);                  // whole URL from user input
  return Response.json({ a, b });
}
""")
    lines = await _ssrf_lines(app)
    assert lines, "a user-controlled fetch host must still be flagged as SSRF"

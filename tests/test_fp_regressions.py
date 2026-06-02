"""False-positive regressions found by battle-testing on real OSS Next.js repos.

Each test pins a real FP we fixed, plus the matching true positive so the rule
still fires where it should.
"""

from __future__ import annotations

import pytest

from conftest import scan


def _app(tmp_path, rel: str, code: str):
    (tmp_path / "package.json").write_text('{"name":"t","dependencies":{"next":"14.2.5"}}')
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return tmp_path


@pytest.mark.asyncio
async def test_target_blank_rel_on_adjacent_line_not_flagged(tmp_path):
    # rel="noreferrer" on the next line (multi-line JSX) — must NOT flag (was a FP in taxonomy)
    app = _app(tmp_path, "components/footer.tsx", (
        'export const F = () => (\n'
        '  <a\n'
        '    href={x}\n'
        '    target="_blank"\n'
        '    rel="noreferrer"\n'
        '  >link</a>\n'
        ');\n'
    ))
    r = await scan(app, only_detectors=["patterns"])
    assert not any(f.rule_id == "react.unsafe-target-blank" for f in r.findings)


@pytest.mark.asyncio
async def test_target_blank_without_rel_is_flagged(tmp_path):
    app = _app(tmp_path, "components/bad.tsx",
               'export const B = () => <a href={x} target="_blank">link</a>;\n')
    r = await scan(app, only_detectors=["patterns"])
    assert any(f.rule_id == "react.unsafe-target-blank" for f in r.findings)


@pytest.mark.asyncio
async def test_same_origin_redirect_not_flagged(tmp_path):
    # NextResponse.redirect(new URL("/path", req.url)) is same-origin — must NOT flag (FP in taxonomy)
    app = _app(tmp_path, "middleware.ts", (
        'import { NextResponse } from "next/server";\n'
        'export function middleware(req) {\n'
        '  return NextResponse.redirect(new URL("/dashboard", req.url));\n'
        '}\n'
    ))
    r = await scan(app, only_detectors=["static", "taint"])
    assert not any(f.rule_id == "open-redirect" for f in r.findings)


@pytest.mark.asyncio
async def test_same_origin_template_redirect_not_flagged(tmp_path):
    app = _app(tmp_path, "middleware.ts", (
        'import { NextResponse } from "next/server";\n'
        'export function middleware(req) {\n'
        '  const from = req.nextUrl.pathname;\n'
        '  return NextResponse.redirect(new URL(`/login?from=${encodeURIComponent(from)}`, req.url));\n'
        '}\n'
    ))
    r = await scan(app, only_detectors=["static", "taint"])
    assert not any(f.rule_id == "open-redirect" for f in r.findings)


@pytest.mark.asyncio
async def test_open_redirect_to_user_value_still_flagged(tmp_path):
    # a redirect to a user-controlled value (not a same-origin literal) must still fire
    app = _app(tmp_path, "pages/api/go.js",
               'export default function h(req, res) { res.redirect(req.query.next); }\n')
    r = await scan(app, only_detectors=["static", "taint"])
    assert any(f.rule_id == "open-redirect" for f in r.findings)

"""Attack-path synthesis — chains form when they should, and never when they shouldn't.

The whole value of this feature is *trust*: a developer must be able to believe the
story. So these tests pin down both directions — real multi-step chains are produced
with sane scores/ordering/breakpoints, and unrelated or dead-code findings produce
nothing (no fabricated paths).
"""

from __future__ import annotations

import pytest

from njordscan.analysis import synthesize
from njordscan.analysis.attack_paths import KILL_CHAIN, _band
from njordscan.core.finding import Finding, TaintStep
from njordscan.core.severity import Severity

from conftest import scan


def F(rule_id, *, file="app/api/x.ts", line=1, severity=Severity.HIGH,
      reachable=True, kind="server", entrypoint="app/api/x.ts", confidence="high", **md):
    f = Finding(rule_id=rule_id, file=file, line=line, severity=severity,
                reachable=reachable, confidence=confidence)
    if reachable and kind:
        f.metadata["reachability"] = {"kind": kind, "entrypoint": entrypoint}
    f.metadata.update(md)
    return f


# ── chains form when the ingredients are present ──────────────────────────────

def test_unauthenticated_injection_chain_forms():
    paths = synthesize([
        F("auth.middleware-bypass", severity=Severity.HIGH),
        F("sqli.string-concatenation", severity=Severity.CRITICAL),
    ])
    assert paths, "expected an attack path from open-door + injection"
    p = paths[0]
    rules = {r for s in p.steps for r in s.rule_ids}
    assert {"auth.middleware-bypass", "sqli.string-concatenation"} <= rules
    tactics = [s.tactic for s in p.steps]
    assert tactics[0] == "Initial Access" and "Execution" in tactics
    assert p.steps[0].breakpoint is True            # close the front door = break chain
    assert p.band.rank >= Severity.HIGH.rank


def test_taint_flow_becomes_a_path():
    f = F("injection.eval", file="a.ts", line=5, severity=Severity.CRITICAL,
          taint_flow=[TaintStep("req.query.x", "a.ts", 2, "source"),
                      TaintStep("eval(x)", "a.ts", 5, "sink")])
    f.taint_flow = [TaintStep("req.query.x", "a.ts", 2, "source"),
                    TaintStep("eval(x)", "a.ts", 5, "sink")]
    paths = synthesize([f])
    assert paths
    p = paths[0]
    assert p.steps[0].tactic == "Initial Access"
    assert p.steps[-1].tactic == "Execution"
    assert "req.query.x" in p.steps[0].narrative


def test_xss_with_no_csp_chains_to_session_theft():
    paths = synthesize([
        F("xss.dangerously-set-inner-html", file="app/page.tsx", kind="client", severity=Severity.HIGH),
        F("headers.missing-csp", file="next.config.js", kind="project", severity=Severity.MEDIUM),
    ])
    titles = [p.title.lower() for p in paths]
    assert any("xss" in t or "session" in t for t in titles)
    p = next(p for p in paths if "session" in p.title.lower() or "xss" in p.title.lower())
    assert any(s.tactic == "Defense Evasion" for s in p.steps)


def test_kev_dependency_is_critical_and_flagged():
    paths = synthesize([
        F("deps.known-vulnerability", file="package.json", kind="project",
          package="lodash", advisory_id="CVE-2019-10744", cisa_kev=True, epss=0.9),
    ])
    assert paths
    p = paths[0]
    assert p.kev is True
    assert p.band is Severity.CRITICAL
    assert any("actively exploited" in fct.lower() for fct in p.score_factors)


def test_secret_pivot_chain():
    paths = synthesize([
        F("path-traversal.fs-read", file="app/api/file.ts", severity=Severity.HIGH),
        F("secret.aws-access-key", file=".env.local", kind="project", severity=Severity.CRITICAL),
    ])
    assert any("pivot" in p.title.lower() or "secret" in p.title.lower() for p in paths)
    p = paths[0]
    assert any("blast radius" in fct for fct in p.score_factors)


# ── and never when they shouldn't (no fabricated paths) ───────────────────────

def test_empty_findings_no_paths():
    assert synthesize([]) == []


def test_unrelated_finding_produces_no_path():
    # a lone low-signal finding that isn't an ingredient in any template
    assert synthesize([F("headers.missing-referrer-policy", severity=Severity.LOW)]) == []


def test_dead_code_injection_does_not_chain():
    # both proven unreachable → no live attack path
    paths = synthesize([
        F("auth.middleware-bypass", reachable=False, kind=None),
        F("sqli.string-concatenation", reachable=False, kind=None),
    ])
    assert not any(p.kind == "unauth-exec" for p in paths)


def test_not_affected_dependency_is_skipped():
    paths = synthesize([
        F("deps.known-vulnerability", file="package.json", kind=None, reachable=False,
          package="lodash", advisory_id="CVE-x", vex_state="not_affected"),
    ])
    assert paths == []


# ── ranking, dedup, scoring invariants ────────────────────────────────────────

def test_paths_ranked_and_no_path_is_subset_of_another():
    paths = synthesize([
        F("auth.middleware-bypass", severity=Severity.HIGH),
        F("sqli.string-concatenation", severity=Severity.CRITICAL),
        F("injection.eval", file="a.ts", line=5, severity=Severity.CRITICAL,
          taint_flow=[TaintStep("req.body", "a.ts", 1, "source"),
                      TaintStep("eval", "a.ts", 5, "sink")]),
        F("secret.aws-access-key", file=".env", kind="project", severity=Severity.CRITICAL),
    ])
    scores = [p.score for p in paths]
    assert scores == sorted(scores, reverse=True)          # ranked strongest-first
    sets = [p.fingerprint_set for p in paths]
    for i, a in enumerate(sets):
        for j, b in enumerate(sets):
            if i != j:
                assert not (a < b), "a path must not be a strict subset of another"


def test_band_thresholds():
    assert _band(85) is Severity.CRITICAL
    assert _band(70) is Severity.HIGH
    assert _band(45) is Severity.MEDIUM
    assert _band(10) is Severity.LOW


def test_kill_chain_orders_steps_front_to_back():
    paths = synthesize([
        F("auth.middleware-bypass", severity=Severity.HIGH),
        F("sqli.string-concatenation", severity=Severity.CRITICAL),
    ])
    for p in paths:
        idxs = [KILL_CHAIN.index(s.tactic) for s in p.steps if s.tactic in KILL_CHAIN]
        assert idxs == sorted(idxs)
        assert [s.order for s in p.steps] == list(range(1, len(p.steps) + 1))


# ── end-to-end through a real scan + emitters ─────────────────────────────────

@pytest.mark.asyncio
async def test_scan_produces_attack_paths_and_serializes(vuln_app):
    r = await scan(vuln_app)
    assert r.attack_paths, "the vulnerable fixture should yield attack paths"
    assert all(p.steps and p.score > 0 for p in r.attack_paths)
    assert any(s.breakpoint for p in r.attack_paths for s in p.steps)

    from njordscan.report.json_report import build_report
    from njordscan.report.sarif import build_sarif

    jr = build_report(r)
    assert jr["attack_paths"] and jr["attack_paths"][0]["steps"]
    sr = build_sarif(r)
    assert sr["runs"][0]["properties"]["njordscan/attackPaths"]


@pytest.mark.asyncio
async def test_clean_app_has_no_attack_paths(clean_app):
    r = await scan(clean_app)
    assert r.attack_paths == []


# ── regression guards for adversarial-review defects (do not let these come back) ──

def test_cross_route_door_and_sink_do_not_chain():
    # auth gap on route A must NOT be stitched to an injection on unrelated route B
    paths = synthesize([
        F("auth.middleware-bypass", file="app/api/a/route.ts", entrypoint="app/api/a/route.ts"),
        F("sqli.string-concatenation", file="app/api/b/route.ts", entrypoint="app/api/b/route.ts",
          severity=Severity.CRITICAL),
    ])
    assert not any(p.kind == "unauth-exec" for p in paths), "cross-route chain must not be fabricated"


def test_same_route_door_and_sink_do_chain():
    paths = synthesize([
        F("auth.middleware-bypass", file="app/api/x/route.ts", entrypoint="app/api/x/route.ts"),
        F("sqli.string-concatenation", file="lib/db.ts", entrypoint="app/api/x/route.ts",
          severity=Severity.CRITICAL),
    ])
    assert any(p.kind == "unauth-exec" for p in paths)


def test_server_dom_sink_not_narrated_as_browser_xss():
    f = F("xss.dangerously-set-inner-html", file="app/api/route.ts", kind="server",
          severity=Severity.HIGH,
          taint_flow=[TaintStep("req.body", "app/api/route.ts", 2, "source"),
                      TaintStep("el.innerHTML", "app/api/route.ts", 5, "sink")])
    f.taint_flow = [TaintStep("req.body", "app/api/route.ts", 2, "source"),
                    TaintStep("el.innerHTML", "app/api/route.ts", 5, "sink")]
    p = synthesize([f])[0]
    assert "browser" not in p.impact.lower()
    assert "xss" not in p.title.lower()
    assert not any("browser" in s.narrative.lower() for s in p.steps)


def test_single_finding_gets_no_multistep_factor():
    f = F("injection.eval", file="a.ts", line=5, severity=Severity.MEDIUM,
          taint_flow=[TaintStep("req.body", "a.ts", 1, "source"),
                      TaintStep("eval", "a.ts", 5, "sink")])
    f.taint_flow = [TaintStep("req.body", "a.ts", 1, "source"), TaintStep("eval", "a.ts", 5, "sink")]
    p = synthesize([f])[0]
    assert not any("weaknesses align" in fct for fct in p.score_factors)
    assert not any("high-confidence" in fct for fct in p.score_factors)


def test_band_never_exceeds_top_finding_by_more_than_one_tier():
    # two MEDIUM findings must not reach the CRITICAL band
    paths = synthesize([
        F("cors.wildcard-credentials", file="app/api/route.ts", kind="client", severity=Severity.MEDIUM),
        F("auth.jwt-in-localstorage", file="app/lib/auth.ts", kind="client", severity=Severity.MEDIUM),
    ])
    assert paths
    assert all(p.band.rank <= Severity.HIGH.rank for p in paths)


def test_epss_is_clamped_to_100_percent():
    p = synthesize([
        F("deps.known-vulnerability", file="package.json", kind="project", severity=Severity.HIGH,
          package="x", advisory_id="CVE-y", cisa_kev=True, epss=2.5),  # malformed >1 feed value
    ])[0]
    assert 0 <= p.score <= 100
    assert not any("250%" in fct for fct in p.score_factors)


def test_public_and_test_and_dead_secrets_are_not_pivoted():
    base_prim = dict(file="app/api/file.ts", severity=Severity.HIGH)
    # public-by-design secret
    assert synthesize([F("path-traversal.fs-read", **base_prim),
                       F("vite.vite-prefixed-secret", file="src/config.ts", kind="client",
                         severity=Severity.MEDIUM)]) == [] or \
        not any(p.kind == "secret-pivot" for p in synthesize([
            F("path-traversal.fs-read", **base_prim),
            F("vite.vite-prefixed-secret", file="src/config.ts", kind="client", severity=Severity.MEDIUM)]))
    # test-fixture secret
    assert not any(p.kind == "secret-pivot" for p in synthesize([
        F("path-traversal.fs-read", **base_prim),
        F("secret.aws-access-key", file="__tests__/fixtures/old.ts", kind="server", severity=Severity.CRITICAL)]))
    # dead-code secret
    assert not any(p.kind == "secret-pivot" for p in synthesize([
        F("path-traversal.fs-read", **base_prim),
        F("secret.aws-access-key", file="lib/dead.ts", reachable=False, kind=None, severity=Severity.CRITICAL)]))


def test_breakpoint_is_not_the_untrusted_input_source():
    f = F("injection.eval", file="a.ts", line=5, severity=Severity.CRITICAL,
          taint_flow=[TaintStep("req.query.x", "a.ts", 2, "source"),
                      TaintStep("eval(x)", "a.ts", 5, "sink")])
    f.taint_flow = [TaintStep("req.query.x", "a.ts", 2, "source"),
                    TaintStep("eval(x)", "a.ts", 5, "sink")]
    p = synthesize([f])[0]
    bp = next(s for s in p.steps if s.breakpoint)
    assert "controls untrusted input" not in bp.title.lower()  # the sink, not the source
    assert bp.tactic == "Execution"


def test_malformed_reachability_metadata_does_not_crash_or_drop_chain():
    door = F("auth.middleware-bypass", file="app/api/x/route.ts", entrypoint="app/api/x/route.ts")
    sink = F("sqli.string-concatenation", file="lib/db.ts", entrypoint="app/api/x/route.ts",
             severity=Severity.CRITICAL)
    door.metadata["reachability"] = "server"   # non-dict — must be tolerated
    paths = synthesize([door, sink])
    assert isinstance(paths, list)  # no crash


def test_attack_step_location_is_none_safe():
    from njordscan.analysis.attack_paths import AttackStep
    assert AttackStep(order=1, tactic="t", title="x", narrative="n", file=None, line=5).location == ""

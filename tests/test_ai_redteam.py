"""AI red-teamer — the LLM proposes, the deterministic engine disposes.

The whole claim of this feature is that the model CANNOT lie: a proposed chain only
survives if every step is a real finding and every edge is grounded in the engine's
own facts. These tests prove exactly that, offline, with a mock provider — no network,
fully deterministic.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from njordscan.analysis import ai_redteam
from njordscan.analysis.attack_paths import AttackPath, synthesize
from njordscan.core.finding import Finding, TaintStep
from njordscan.core.severity import Severity


class FakeProvider:
    """A stand-in LLM that returns a preset response (no network)."""

    name = "fake"
    is_local = True

    def __init__(self, payload: str) -> None:
        self._payload = payload

    def check(self):
        return True, ""

    def complete(self, system: str, user: str, *, timeout: float = 60.0) -> str:
        return self._payload


def F(rule_id, *, file="app/api/x/route.ts", line=1, severity=Severity.HIGH,
      reachable=True, kind="server", entrypoint="app/api/x/route.ts", **md):
    f = Finding(rule_id=rule_id, file=file, line=line, severity=severity,
                reachable=reachable, confidence="high")
    f.title = rule_id
    if reachable and kind:
        f.metadata["reachability"] = {"kind": kind, "entrypoint": entrypoint}
    f.metadata.update(md)
    return f


def _result(findings):
    return SimpleNamespace(findings=findings)


def _cfg():
    return SimpleNamespace(ai_provider="ollama", ai_redact=True, no_external=False)


def _chains_json(*chains):
    return json.dumps({"chains": [
        {"steps": list(s), "title": "t", "impact": "i", "reasoning": "r"} for s in chains
    ]})


# ── the model proposes a real chain → it verifies and renders ─────────────────

def test_valid_chain_passes_verification():
    door = F("auth.middleware-bypass")
    sink = F("sqli.tainted-query", file="lib/db.ts")        # same entrypoint as door
    secret = F("secret.aws-access-key", file=".env", kind="project")
    findings = [door, sink, secret]
    provider = FakeProvider(_chains_json([door.fingerprint, sink.fingerprint, secret.fingerprint]))

    paths = ai_redteam.redteam(_result(findings), _cfg(), provider=provider)
    assert len(paths) == 1
    p = paths[0]
    assert isinstance(p, AttackPath)
    assert p.ai_verified is True and p.kind == "ai-verified"
    assert len(p.steps) == 3
    assert len(p.verification) == 2          # one grounding reason per edge
    assert p.id == "ai-path-1"


# ── the model CANNOT lie ──────────────────────────────────────────────────────

def test_hallucinated_finding_id_is_dropped():
    door = F("auth.middleware-bypass")
    secret = F("secret.aws-access-key", file=".env", kind="project")
    provider = FakeProvider(_chains_json([door.fingerprint, "deadbeefdeadbeef", secret.fingerprint]))
    paths = ai_redteam.redteam(_result([door, secret]), _cfg(), provider=provider)
    # the fake id is silently dropped; the real, grounded door→secret link remains
    assert len(paths) == 1
    assert all("deadbeef" not in fp for s in paths[0].steps for fp in s.fingerprints)


def test_all_fake_ids_yield_nothing():
    door = F("auth.middleware-bypass")
    provider = FakeProvider(_chains_json(["nope1", "nope2", "nope3"]))
    assert ai_redteam.redteam(_result([door, F("sqli.tainted-query", file="lib/db.ts")]),
                              _cfg(), provider=provider) == []


def test_ungrounded_edge_voids_the_chain():
    # a secret and an unrelated client-side XSS on a different surface do not compose
    secret = F("secret.aws-access-key", file=".env", kind="project", entrypoint=None)
    xss = F("xss.dangerously-set-inner-html", file="app/page.tsx", kind="client",
            entrypoint="app/page.tsx")
    provider = FakeProvider(_chains_json([secret.fingerprint, xss.fingerprint]))
    assert ai_redteam.redteam(_result([secret, xss]), _cfg(), provider=provider) == []


def test_chain_with_no_impact_is_rejected():
    # two pure defense-gaps reach no concrete impact → not an attack
    csp = F("headers.missing-csp", file="next.config.js", kind="project", severity=Severity.MEDIUM)
    cors = F("cors.wildcard-credentials", file="app/api/x/route.ts", severity=Severity.MEDIUM)
    provider = FakeProvider(_chains_json([csp.fingerprint, cors.fingerprint]))
    assert ai_redteam.redteam(_result([csp, cors]), _cfg(), provider=provider) == []


# ── robustness ────────────────────────────────────────────────────────────────

def test_garbage_model_output_is_safe():
    f = [F("auth.middleware-bypass"), F("sqli.tainted-query", file="lib/db.ts")]
    for payload in ["not json at all", "", "```\nnonsense\n```", "{}", '{"chains": "x"}']:
        assert ai_redteam.redteam(_result(f), _cfg(), provider=FakeProvider(payload)) == []


def test_parse_handles_fenced_json():
    door = F("auth.middleware-bypass")
    secret = F("secret.aws-access-key", file=".env", kind="project")
    fenced = "```json\n" + _chains_json([door.fingerprint, secret.fingerprint]) + "\n```"
    paths = ai_redteam.redteam(_result([door, secret]), _cfg(), provider=FakeProvider(fenced))
    assert len(paths) == 1


def test_too_few_findings_returns_empty():
    assert ai_redteam.redteam(_result([F("auth.middleware-bypass")]), _cfg(),
                              provider=FakeProvider(_chains_json())) == []


def test_dedupes_against_existing_template_paths():
    door = F("auth.middleware-bypass")
    sink = F("sqli.tainted-query", file="lib/db.ts")
    secret = F("secret.aws-access-key", file=".env", kind="project")
    findings = [door, sink, secret]
    existing = synthesize(findings)   # the deterministic templates already cover these
    provider = FakeProvider(_chains_json([door.fingerprint, sink.fingerprint]))
    # the AI chain is a subset of a template path's findings → suppressed
    paths = ai_redteam.redteam(_result(findings), _cfg(), provider=provider, existing=existing)
    assert paths == []


def test_inventory_excludes_code_and_roleless_findings():
    door = F("auth.middleware-bypass")
    door.code_snippet = "const SECRET = 'should-not-be-sent'"
    roleless = F("headers.missing-referrer-policy", severity=Severity.LOW)
    inv, by_id = ai_redteam._inventory([door, roleless], redact=False)
    blob = json.dumps(inv)
    assert "should-not-be-sent" not in blob          # no code snippets in the inventory
    assert all(it["type"] != "headers.missing-referrer-policy" for it in inv)  # no-role excluded

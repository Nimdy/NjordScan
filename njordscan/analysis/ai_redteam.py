"""AI red-teamer — the LLM proposes attack chains, the deterministic engine verifies.

The attack-path *templates* find the chains we hand-coded. A language model can
recombine the SAME confirmed findings into novel, longer, cross-category chains the
templates never enumerate — an attacker's imagination over a fixed set of facts.

But a language model hallucinates. So this module treats the model as a *suspect*:
it may only reference findings we actually produced (by id), and **every edge it
claims between two steps is checked against the real reachability / roles / data-flow
and discarded if it cannot be grounded**. The model can reorder and connect verified
facts; it cannot invent a vulnerability, cite a finding that does not exist, or assert
a link the engine can't independently confirm. What survives is, by construction,
backed end-to-end by your own code.

Opt-in (needs an AI provider); offline by default. Pure verification logic is testable
without a network via an injected provider.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from ..core.finding import Finding
from . import attack_paths as ap

logger = logging.getLogger(__name__)

_MAX_FINDINGS = 60      # cap the inventory we hand the model (token budget + focus)
_MAX_CHAINS = 6         # keep the strongest verified chains
_MAX_STEPS = 6          # a sane upper bound on chain length


# ── 1. inventory: the verifiable substrate handed to the model ────────────────

def _capabilities(f: Finding) -> List[str]:
    return sorted(ap._roles(f))


def _inventory(findings: List[Finding], *, redact: bool) -> Tuple[List[Dict[str, Any]], Dict[str, Finding]]:
    """A compact, code-free description of each finding the model may use as a step."""
    from ..explain.redact import redact as _redact

    items: List[Dict[str, Any]] = []
    by_id: Dict[str, Finding] = {}
    # prefer reachable, higher-severity, capability-bearing findings
    ranked = sorted(
        findings,
        key=lambda f: (-f.effective_severity.rank, f.reachable is not True, f.file, f.line),
    )
    for f in ranked:
        caps = _capabilities(f)
        if not caps:
            continue  # only findings that can play a role in a chain
        fid = f.fingerprint
        if fid in by_id:
            continue
        by_id[fid] = f
        reach = ap._reach(f)
        msg = f.message or f.title
        items.append({
            "id": fid,
            "type": f.rule_id,
            "what": _redact(msg) if redact else msg,
            "file": f.file,
            "line": f.line,
            "severity": f.effective_severity.value,
            "capabilities": caps,
            "reachable": f.reachable,
            "surface": reach.get("kind"),            # server | client | project | None
            "entrypoint": reach.get("entrypoint"),
            "data_asset": f.metadata.get("data_asset"),
            "actively_exploited": bool(f.metadata.get("cisa_kev")),
        })
        if len(items) >= _MAX_FINDINGS:
            break
    return items, by_id


# ── 2. deterministic edge grounding (the part the model cannot fake) ──────────

def _edge_grounded(a: Finding, b: Finding) -> Optional[str]:
    """Return a human reason iff a real attacker advances from finding ``a`` to ``b``.

    Mirrors the grounding the templates use, generalised so any two findings can be
    checked. Returns None when the link is not supported by the engine's facts — that
    edge (and the chain that needs it) is then rejected. Order matters."""
    ra, rb = ap._roles(a), ap._roles(b)
    ea, eb = ap._entrypoint(a), ap._entrypoint(b)

    # same exposed surface — both reachable from the same entrypoint
    if ea and eb and ea == eb and ap._is_reachable(a) and ap._is_reachable(b):
        return f"both reachable from the same entrypoint ({ea})"

    # an access-control gap exposes whatever is reachable behind it
    if "open_door" in ra and ap._is_reachable(b):
        return "the missing authentication exposes the next step's surface"

    # a server-side primitive (exec / SSRF / file-read) can reach an exposed secret
    if ({"code_exec"} & ra) and ap._is_server(a) and ({"secret", "sensitive_egress"} & rb):
        return "the server-side primitive can read the exposed secret/credential"

    # a missing browser control unleashes script execution / token theft
    if ({"weak_csp", "open_cors"} & ra) and ({"browser_exec", "token_store"} & rb):
        return "the missing browser-side control unleashes the next step"

    # script execution in the page can read a token kept in the page
    if ("browser_exec" in ra) and ({"token_store", "data_leak", "sensitive_egress"} & rb):
        return "script execution can read the exposed client-side data"

    # a held secret/credential enables exfiltration or lateral movement
    if ({"secret"} & ra) and ({"sensitive_egress", "data_leak"} & rb):
        return "the exposed credential is what gets carried out"

    # data-flow continuation: a's sink lands in the file where b operates
    if a.taint_flow and b.file and a.taint_flow[-1].file == b.file and a.fingerprint != b.fingerprint:
        return "data flows from the first step into the second step's location"

    return None


# ── 3. verify a proposed chain against ground truth ───────────────────────────

_IMPACT_ROLES = {"code_exec", "browser_exec", "secret", "sensitive_egress",
                 "data_leak", "token_store", "vuln_dep", "supply_foothold"}


def _verify_chain(step_ids: List[str], by_id: Dict[str, Finding]
                  ) -> Optional[Tuple[List[Finding], List[str]]]:
    """Resolve + verify a proposed chain. Returns (findings, per-edge reasons) or None.

    Drops hallucinated step ids, rejects the chain if any surviving edge is ungrounded,
    if fewer than two real steps remain, or if it never reaches a real impact."""
    seen: set = set()
    chain: List[Finding] = []
    for sid in step_ids:
        f = by_id.get(sid)
        if f is None or f.fingerprint in seen:   # hallucinated or duplicate → drop the step
            continue
        seen.add(f.fingerprint)
        chain.append(f)
        if len(chain) >= _MAX_STEPS:
            break
    if len(chain) < 2:
        return None
    reasons: List[str] = []
    for a, b in zip(chain, chain[1:]):
        why = _edge_grounded(a, b)
        if why is None:
            return None  # an unverifiable link voids the whole chain
        reasons.append(f"{a.rule_id} → {b.rule_id}: {why}")
    if not any(_IMPACT_ROLES & ap._roles(f) for f in chain):
        return None  # a chain that reaches no impact is not an attack
    return chain, reasons


# ── 4. step / path construction (preserves the verified order) ────────────────

_TACTIC_BY_ROLE = [
    ("open_door", "Initial Access"), ("supply_foothold", "Initial Access"),
    ("vuln_dep", "Initial Access"), ("weak_csp", "Defense Evasion"),
    ("open_cors", "Defense Evasion"), ("code_exec", "Execution"),
    ("browser_exec", "Execution"), ("secret", "Credential Access"),
    ("token_store", "Credential Access"), ("sensitive_egress", "Exfiltration"),
    ("data_leak", "Collection"),
]


def _tactic_for(f: Finding) -> str:
    roles = ap._roles(f)
    for role, tactic in _TACTIC_BY_ROLE:
        if role in roles:
            return tactic
    return "Execution"


def _build_path(chain: List[Finding], reasons: List[str], title: str, impact: str) -> ap.AttackPath:
    steps: List[ap.AttackStep] = []
    for i, f in enumerate(chain, start=1):
        steps.append(ap.AttackStep(
            order=i, tactic=_tactic_for(f), title=f.title or f.rule_id,
            narrative=f.message or f.title or f.rule_id,
            file=f.file, line=f.line, rule_ids=[f.rule_id], fingerprints=[f.fingerprint],
            breakpoint=(i == 1),
        ))
    distinct = len({f.fingerprint for f in chain})
    score, factors, kev = ap._score_path(chain, reaches_impact=True, distinct_findings=distinct)
    techniques: List[str] = []
    for f in chain:
        for t in f.attack:
            if t not in techniques:
                techniques.append(t)
    advice = (f"Break the chain at step 1 — fix {steps[0].title.lower()} ({steps[0].location}). "
              "Cutting the first link collapses the chain.") if steps else ""
    return ap.AttackPath(
        id="ai", kind="ai-verified", title=title, impact=impact, score=score,
        band=ap._band(score), steps=steps, advice=advice, score_factors=factors,
        technique_ids=techniques, kev=kev, ai_verified=True, verification=reasons,
    )


# ── 5. the LLM prompt ─────────────────────────────────────────────────────────

_SYSTEM = (
    "You are a meticulous penetration tester. You are given a list of CONFIRMED "
    "weaknesses already found in a web app, each with a stable id, type, location, "
    "and capability tags. Your job: propose realistic multi-step ATTACK CHAINS where "
    "each step plausibly enables the next and the chain ends in a concrete impact "
    "(data theft, account takeover, code execution, secret exfiltration). "
    "HARD RULES: (1) every step MUST be one of the given finding ids — never invent a "
    "step or an id; (2) order steps the way an attacker actually proceeds; (3) prefer "
    "chains that cross categories (e.g. an auth gap that exposes an injection that "
    "reaches a secret that gets exfiltrated); (4) it is fine to return few or zero "
    "chains if nothing genuinely composes. Output STRICT JSON only."
)

_OUTPUT_SHAPE = (
    '{"chains": [{"steps": ["<finding id>", "..."], "title": "<short attack name>", '
    '"impact": "<one-line outcome>", "reasoning": "<why each step enables the next>"}]}'
)


def _prompt(inventory: List[Dict[str, Any]]) -> str:
    return (
        "Confirmed findings (you may only use these ids as steps):\n"
        + json.dumps(inventory, indent=1)
        + "\n\nPropose up to 6 attack chains. Respond with JSON exactly in this shape "
          "and nothing else:\n" + _OUTPUT_SHAPE
    )


def _parse(text: str) -> List[Dict[str, Any]]:
    """Best-effort extract the chains array from a model response."""
    if not text:
        return []
    s = text.strip()
    if s.startswith("```"):
        s = s.strip("`")
        s = s.split("\n", 1)[1] if "\n" in s else s
    # find the outermost JSON object
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end == -1:
        return []
    try:
        data = json.loads(s[start:end + 1])
    except (ValueError, json.JSONDecodeError):
        return []
    chains = data.get("chains") if isinstance(data, dict) else None
    return chains if isinstance(chains, list) else []


# ── 6. orchestration ──────────────────────────────────────────────────────────

def redteam(result, config, *, provider=None, existing: Optional[List["ap.AttackPath"]] = None
            ) -> List["ap.AttackPath"]:
    """Run the AI red-teamer and return ONLY chains whose every step + edge verified.

    ``provider`` may be injected (for tests / reuse); otherwise it is resolved from
    config. Never raises — returns ``[]`` on any error, no findings, or no provider."""
    findings = [f for f in result.findings if ap._roles(f)]
    if len(findings) < 2:
        return []
    try:
        redact = False
        if provider is None:
            from ..explain.providers import get_provider, is_remote
            name = config.ai_provider or "ollama"
            if is_remote(name) and getattr(config, "no_external", False):
                return []
            provider = get_provider(name)
            ok, _reason = provider.check()
            if not ok:
                return []
            redact = is_remote(name) and getattr(config, "ai_redact", True)

        inventory, by_id = _inventory(findings, redact=redact)
        if len(inventory) < 2:
            return []
        raw = provider.complete(_SYSTEM, _prompt(inventory))
        proposed = _parse(raw)
    except Exception as exc:  # noqa: BLE001 — red-team is best-effort, never breaks a scan
        logger.debug("ai redteam unavailable: %s", exc)
        return []

    # existing template paths to dedupe against (don't re-report a known chain)
    seen_sets: List[frozenset] = [p.fingerprint_set for p in (existing or [])]
    out: List["ap.AttackPath"] = []
    for ch in proposed:
        if not isinstance(ch, dict):
            continue
        ids = ch.get("steps")
        if not isinstance(ids, list):
            continue
        verified = _verify_chain([str(x) for x in ids], by_id)
        if verified is None:
            continue
        chain, reasons = verified
        fps = frozenset(f.fingerprint for f in chain)
        # suppress only if this chain adds nothing over an existing one (it is a
        # subset). A RICHER chain that merely contains a template's findings is novel.
        if any(fps <= s for s in seen_sets):
            continue
        seen_sets.append(fps)
        title = str(ch.get("title") or "AI-discovered attack chain")[:120]
        impact = str(ch.get("impact") or "Compromise via a verified multi-step chain")[:200]
        out.append(_build_path(chain, reasons, title, impact))
        if len(out) >= _MAX_CHAINS:
            break

    out.sort(key=lambda p: (-p.score, -len(p.steps)))
    for i, p in enumerate(out, start=1):
        p.id = f"ai-path-{i}"
    return out

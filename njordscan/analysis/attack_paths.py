"""Attack-path synthesis — turn a pile of findings into the *story* of a breach.

Every other scanner hands you a flat list: "40 issues, here they are." A developer
who isn't a security expert has no way to know which three of those forty actually
chain together into a real-world compromise — or that fixing *one* of them collapses
the whole chain.

This module composes individual findings into **attack paths**: ordered, plain-English
kill chains ("Step 1: anyone can call this route → Step 2: it runs your SQL → Step 3:
they read your users table"), each scored by a transparent exploitability model and
annotated with the single cheapest place to **break the chain**.

The synthesis is deliberately *conservative*: every step is backed by a real finding
at a real file:line, chains prefer findings proven **reachable** from a framework
entrypoint, and the score factors are shown rather than hidden behind a magic number.
A path is a strong hypothesis about how an attacker proceeds — not a proof — and it
says so.

Pure, dependency-free, and fast (O(findings) classification + bounded template
combinations). Returns an empty list rather than ever raising.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.finding import Finding
from ..core.severity import Severity

# ── MITRE ATT&CK kill-chain order ──────────────────────────────────────────────
# The code base has no canonical tactic ordering, so we define the Enterprise one
# here. A finding's "stage" is the earliest tactic any of its techniques belongs to;
# steps in a path are emitted in this order so the narrative reads front-to-back.
KILL_CHAIN: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
_STAGE = {name: i for i, name in enumerate(KILL_CHAIN)}


def _stage_index(tactic: str) -> int:
    return _STAGE.get(tactic, len(KILL_CHAIN))  # unknown tactics sort last


# ── data model ─────────────────────────────────────────────────────────────────

@dataclass
class AttackStep:
    """One move in an attack path, backed by one or more real findings."""

    order: int
    tactic: str               # the ATT&CK tactic this move belongs to
    title: str                # short label, e.g. "Unauthenticated API route"
    narrative: str            # plain-English: what the attacker does here
    file: str
    line: int
    rule_ids: List[str] = field(default_factory=list)
    fingerprints: List[str] = field(default_factory=list)
    breakpoint: bool = False  # ★ fixing this step alone collapses the chain

    @property
    def location(self) -> str:
        f = self.file or ""
        return f"{f}:{self.line}" if (f and self.line) else f

    def to_dict(self) -> Dict[str, Any]:
        return {
            "order": self.order,
            "tactic": self.tactic,
            "title": self.title,
            "narrative": self.narrative,
            "file": self.file,
            "line": self.line,
            "location": self.location,
            "rule_ids": list(self.rule_ids),
            "fingerprints": list(self.fingerprints),
            "breakpoint": self.breakpoint,
        }


@dataclass
class AttackPath:
    """A scored, ordered chain of steps an attacker could walk to an impact."""

    id: str
    title: str
    impact: str               # one-line outcome, e.g. "Full database compromise"
    score: int                # 0-100 exploitability/blast-radius
    band: Severity            # severity band derived from the score (for colour/emoji)
    steps: List[AttackStep]
    advice: str               # the "break the chain here" recommendation
    kind: str = ""            # stable template id (e.g. "unauth-exec"); survives renumbering
    score_factors: List[str] = field(default_factory=list)  # why the score is what it is
    technique_ids: List[str] = field(default_factory=list)
    kev: bool = False         # involves an actively-exploited (CISA KEV) component

    @property
    def fingerprint_set(self) -> frozenset:
        return frozenset(fp for s in self.steps for fp in s.fingerprints)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "impact": self.impact,
            "score": self.score,
            "band": self.band.value,
            "kev": self.kev,
            "advice": self.advice,
            "score_factors": list(self.score_factors),
            "techniques": list(self.technique_ids),
            "steps": [s.to_dict() for s in self.steps],
        }


# ── finding → capability role classification ──────────────────────────────────
# Each role is a part an attacker can use in a chain. Classification is by rule-id
# prefix + explicit ids, refined by taint data-flow and metadata. Kept conservative.

# Genuine *access-control* gaps only — an unauthenticated attacker can reach the
# surface. Rate-limit / CSRF / dev-origin issues are real but are NOT "no auth", so
# they are deliberately excluded here to avoid mislabeling a chain "unauthenticated".
_OPEN_DOOR_IDS = {
    "auth.middleware-bypass", "ai.endpoint-no-auth", "ai-endpoint.unauthenticated-live",
}
_CODE_EXEC_PREFIX = ("injection.", "sqli.", "nosqli.", "ssrf.", "path-traversal.")
_CODE_EXEC_IDS = {"hardening.insecure-deserialization"}
_BROWSER_EXEC_PREFIX = ("xss.", "dom.")
_BROWSER_EXEC_IDS = {
    "react.ref-inner-html", "react.javascript-url", "react.href-user-value",
    "react.unsanitized-markdown", "dast.reflected-xss", "nextjs.image-dangerously-allow-svg",
    "ai.llm-output-rendered-as-html", "ai.llm-output-to-sink",
}
_CSP_IDS = {"csp.unsafe-inline", "csp.unsafe-eval", "csp.disabled-in-helmet",
            "headers.missing-csp", "config.missing-security-headers"}
_CORS_OPEN_IDS = {"cors.wildcard-credentials", "cors.wildcard-with-credentials",
                  "cors.origin-reflection", "cors.permissive-middleware",
                  "nextjs.api-wildcard-cors", "vite.dev-server-cors-wildcard"}
_SECRET_PREFIX = ("secret.", "crypto.hardcoded", "jwt.hardcoded", "session.hardcoded",
                  "auth.hardcoded")
_SECRET_IDS = {
    "hardening.env-committed", "hardening.env-not-gitignored",
    "hardening.dev-only-branch-shipping-secret-bypass",
    "vite.define-inlines-secret", "vite.import-meta-env-secret", "vite.vite-prefixed-secret",
    "nextjs.api-env-exposure", "nextjs.props-secret-leak",
}
_DATA_LEAK_PREFIX = ("info-leak.",)
_DATA_LEAK_IDS = {"nextjs.error-stack-leak", "nextjs.source-maps-exposed",
                  "vite.prod-sourcemap", "hardening.source-map-shipped-to-prod"}
_TOKEN_STORE_IDS = {"react.token-in-web-storage", "auth.jwt-in-localstorage"}
_VULN_DEP_IDS = {"deps.known-vulnerability"}
_SUPPLY_PREFIX = ("supply-chain.",)


def _roles(f: Finding) -> Set[str]:
    rid = f.rule_id
    roles: Set[str] = set()
    if rid in _OPEN_DOOR_IDS:
        roles.add("open_door")
    if rid.startswith(_CODE_EXEC_PREFIX) or rid in _CODE_EXEC_IDS:
        roles.add("code_exec")
    if rid.startswith(_BROWSER_EXEC_PREFIX) or rid in _BROWSER_EXEC_IDS:
        roles.add("browser_exec")
    if rid in _CSP_IDS:
        roles.add("weak_csp")
    if rid in _CORS_OPEN_IDS:
        roles.add("open_cors")
    if rid.startswith(_SECRET_PREFIX) or rid in _SECRET_IDS:
        roles.add("secret")
    if rid.startswith(_DATA_LEAK_PREFIX) or rid in _DATA_LEAK_IDS:
        roles.add("data_leak")
    if rid in _TOKEN_STORE_IDS:
        roles.add("token_store")
    if rid in _VULN_DEP_IDS:
        roles.add("vuln_dep")
    if rid.startswith(_SUPPLY_PREFIX):
        roles.add("supply_foothold")
    return roles


# ── reachability helpers ──────────────────────────────────────────────────────

def _reach(f: Finding) -> Dict[str, Any]:
    r = f.metadata.get("reachability")
    return r if isinstance(r, dict) else {}  # tolerate a malformed metadata value


def _is_reachable(f: Finding) -> bool:
    """True unless reachability analysis *proved* this finding is dead code."""
    return f.reachable is not False


def _is_server(f: Finding) -> bool:
    return f.reachable is True and _reach(f).get("kind") in ("server", "project")


def _is_client(f: Finding) -> bool:
    """Reachable specifically on the client/browser surface (not server)."""
    return f.reachable is True and _reach(f).get("kind") == "client"


def _entrypoint(f: Finding) -> Optional[str]:
    return _reach(f).get("entrypoint")


def _kev(f: Finding) -> bool:
    return bool(f.metadata.get("cisa_kev"))


def _epss(f: Finding) -> float:
    val = f.metadata.get("epss")
    try:
        # EPSS is a probability in [0,1]; clamp so a malformed feed (a percentile like
        # 87, or 2.5) can never render as "8700%"/"250%" exploit probability.
        return max(0.0, min(1.0, float(val))) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


# Secrets that are *public by design* — shipping a VITE_/NEXT_PUBLIC_ value to the
# browser is its own finding, but such a value is not a server-only credential a
# server-side primitive could "reach", so it must not feed the secret-pivot chain.
_PUBLIC_SECRET_IDS = {
    "vite.vite-prefixed-secret", "vite.import-meta-env-secret",
    "secret.public-env-exposure", "nextjs.api-env-exposure",
}

_TEST_PATH_MARKERS = ("__tests__/", "__mocks__/", "/test/", "/tests/", "fixtures/",
                      ".test.", ".spec.", "/__fixtures__/", "e2e/", "cypress/")


def _is_test_path(path: str) -> bool:
    p = "/" + (path or "").replace("\\", "/").lstrip("/")
    return any(m in p for m in _TEST_PATH_MARKERS)


# ── scoring ───────────────────────────────────────────────────────────────────

_BASE = {Severity.CRITICAL: 62, Severity.HIGH: 50, Severity.MEDIUM: 34,
         Severity.LOW: 18, Severity.INFO: 8}


# A path may be banded at most ONE notch above its most-severe contributing finding.
# Otherwise stacked context bonuses could label a chain "critical" when no single
# underlying issue is worse than medium — the band is the signal a non-expert reads,
# so it must never over-state the worst real finding.
_BAND_CEILING_SCORE = {
    Severity.CRITICAL: 100, Severity.HIGH: 100, Severity.MEDIUM: 79,
    Severity.LOW: 59, Severity.INFO: 39,
}


def _score_path(findings: List[Finding], reaches_impact: bool,
                distinct_findings: int) -> Tuple[int, List[str], bool]:
    """Return (score 0-100, human factors, kev_involved). Transparent on purpose.

    ``distinct_findings`` is the count of *distinct* findings backing the path (not
    narrative steps), so a single-finding chain never earns "multiple weaknesses
    align". The score is capped so the band can't exceed the worst finding by more
    than one tier.
    """
    if not findings:
        return 0, [], False
    top = max(findings, key=lambda f: f.effective_severity.rank)
    score = _BASE[top.effective_severity]
    factors = [f"{top.effective_severity.value} finding ({top.rule_id})"]

    kev = any(_kev(f) for f in findings)
    epss = max((_epss(f) for f in findings), default=0.0)
    server = any(_is_server(f) for f in findings)
    client_reachable = any(_is_client(f) for f in findings)
    secret = any(("secret" in _roles(f)) and f.rule_id not in _PUBLIC_SECRET_IDS
                 for f in findings)

    if server:
        score += 16
        factors.append("server-side reachable from an entrypoint")
    elif client_reachable:
        score += 6
        factors.append("reachable from the client surface")
    # Only penalise when we *analysed* reachability and proved it dead — never when
    # reachability simply wasn't run (reachable is None).
    if findings and all(f.reachable is False for f in findings):
        score -= 22
        factors.append("not reachable from any known entrypoint (lower priority)")

    if kev:
        score += 20
        factors.append("component is actively exploited in the wild (CISA KEV)")
    if epss > 0:
        bump = round(min(15.0, epss * 15))
        if bump:
            score += bump
            factors.append(f"{epss:.0%} 30-day exploit probability (EPSS)")

    if reaches_impact:
        score += 8
        factors.append("chain reaches a concrete impact (data/system compromise)")
    if secret:
        score += 8
        factors.append("exposes a credential — blast radius beyond this app")
    if distinct_findings >= 2:
        bonus = min(12, distinct_findings * 4)
        score += bonus
        factors.append(f"{distinct_findings} distinct weaknesses align into one chain")
        if all(f.confidence == "high" for f in findings):
            score += 4
            factors.append("every step is high-confidence")

    score = max(0, min(100, score))
    # band ceiling: never more than one tier above the worst finding
    score = min(score, _BAND_CEILING_SCORE[top.effective_severity])
    return score, factors, kev


def _band(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


# ── step / path builders ──────────────────────────────────────────────────────

def _step(f: Finding, tactic: str, title: str, narrative: str) -> AttackStep:
    return AttackStep(
        order=0, tactic=tactic, title=title, narrative=narrative,
        file=f.file, line=f.line, rule_ids=[f.rule_id], fingerprints=[f.fingerprint],
    )


def _finalize(pid: str, title: str, impact: str, raw_steps: List[AttackStep],
              findings: List[Finding], *, reaches_impact: bool,
              break_on: Optional[AttackStep] = None, fix_hint: str = "") -> AttackPath:
    # order steps along the kill chain (stable within a tactic)
    ordered = sorted(raw_steps, key=lambda s: _stage_index(s.tactic))
    for i, s in enumerate(ordered, start=1):
        s.order = i
    distinct = len({f.fingerprint for f in findings})
    score, factors, kev = _score_path(findings, reaches_impact, distinct_findings=distinct)

    # break-the-chain: the cheapest *actionable* fix. Never the "attacker controls
    # input" source step (you can't stop users from sending input) — templates point
    # us at the real control (auth, the sink, the CSP/CORS config).
    target = break_on if break_on in ordered else _default_break_step(ordered)
    advice = ""
    if target is not None:
        target.breakpoint = True
        what = fix_hint or f"fix {target.title.lower()}"
        advice = (f"Break the chain at step {target.order} — {what} ({target.location}). "
                  "Fixing that one thing stops this whole path.")

    techniques: List[str] = []
    for f in findings:
        for t in f.attack:
            if t not in techniques:
                techniques.append(t)
    kind = re.sub(r"-[0-9a-f]{16}", "", pid)  # strip fingerprints → stable template id
    return AttackPath(
        id=pid, kind=kind, title=title, impact=impact, score=score, band=_band(score),
        steps=ordered, advice=advice, score_factors=factors,
        technique_ids=techniques, kev=kev,
    )


def _default_break_step(ordered: List[AttackStep]) -> Optional[AttackStep]:
    """The earliest step that represents something a developer can actually change —
    i.e. not a pure 'attacker supplies input' source step."""
    for s in ordered:
        if s.tactic == "Initial Access" and "controls untrusted input" in s.title.lower():
            continue
        return s
    return ordered[0] if ordered else None


def _most_severe(findings: List[Finding]) -> Finding:
    return max(findings, key=lambda f: (f.effective_severity.rank, f.reachable is True))


# ── chain templates ───────────────────────────────────────────────────────────
# Each template inspects the classified findings and yields zero or more candidate
# paths. Templates are intentionally narrow and well-justified; breadth comes from
# having many of them, not from one template guessing wildly.

def _t_taint_flow(ctx: "_Ctx") -> List[AttackPath]:
    """A proven source→sink data flow IS a ready-made attack path."""
    out: List[AttackPath] = []
    for f in ctx.findings:
        if not f.taint_flow or f.reachable is False:
            continue
        src = f.taint_flow[0]
        sink = f.taint_flow[-1]
        # Only call it browser XSS when the sink is reachable on the CLIENT. A DOM
        # sink inside a server API handler doesn't run in anyone's browser.
        is_browser = ("browser_exec" in _roles(f)) and not _is_server(f)
        impact = ("Cross-site scripting in your users' browsers"
                  if is_browser else "Server-side code/query execution")
        entry = _entrypoint(f)
        where = f" reaching {entry}" if entry else ""
        s1 = AttackStep(
            order=0, tactic="Initial Access",
            title="Attacker controls untrusted input",
            narrative=(f"An attacker supplies a value via `{src.label}` "
                       f"({src.file}:{src.line}){where}. Nothing about this input is trusted."),
            file=src.file, line=src.line, rule_ids=[f.rule_id], fingerprints=[f.fingerprint],
        )
        sink_tail = ("runs in the victim's browser" if is_browser
                     else "the attacker now controls what the server runs")
        s2 = AttackStep(
            order=0, tactic="Execution",
            title="Untrusted input reaches a dangerous sink",
            narrative=(f"That value flows unsanitised into `{sink.label}` "
                       f"({sink.file}:{sink.line}) — {sink_tail}."),
            file=sink.file, line=sink.line, rule_ids=[f.rule_id], fingerprints=[f.fingerprint],
        )
        fix = ("encode/sanitise the value before it reaches the sink" if is_browser
               else "validate or parameterise the value at the sink")
        out.append(_finalize(
            f"taint-{f.fingerprint}",
            title=("Reflected XSS via untrusted input" if is_browser
                   else f"Injection via untrusted input → {sink.label}"),
            impact=impact, raw_steps=[s1, s2], findings=[f], reaches_impact=True,
            break_on=s2, fix_hint=fix,
        ))
    return out


def _t_unauth_exec(ctx: "_Ctx") -> List[AttackPath]:
    """An open door (no auth) in front of a code/query-execution sink ON THE SAME ROUTE.

    We only claim "unauthenticated injection" when the auth gap and the sink share an
    entrypoint — defeating auth on route A grants nothing toward an injection on an
    unrelated route B, so cross-route pairs are deliberately NOT chained.
    """
    doors = [f for f in ctx.by_role("open_door") if _is_reachable(f) and _entrypoint(f)]
    sinks = [f for f in ctx.by_role("code_exec") if _is_reachable(f) and _entrypoint(f)]
    if not doors or not sinks:
        return []
    # index sinks by entrypoint (O(1) partner lookup, no quadratic scan)
    sinks_by_entry: Dict[str, List[Finding]] = {}
    for s in sinks:
        sinks_by_entry.setdefault(_entrypoint(s), []).append(s)
    # one most-severe door per entrypoint, so duplicate auth gaps don't spawn dup paths
    door_by_entry: Dict[str, Finding] = {}
    for d in doors:
        e = _entrypoint(d)
        if e not in door_by_entry or d.effective_severity.rank > door_by_entry[e].effective_severity.rank:
            door_by_entry[e] = d

    out: List[AttackPath] = []
    for entry, door in door_by_entry.items():
        partners = sinks_by_entry.get(entry)
        if not partners:
            continue  # no sink on this same surface → no honest chain
        sink = _most_severe(partners)
        s1 = _step(door, "Initial Access", "No authentication on the entry point",
                   f"An unauthenticated attacker reaches {entry} — "
                   f"{door.title.lower()} ({door.location}) leaves it open to anyone.")
        s2 = _step(sink, "Execution", "Attacker-controlled data hits a query/command",
                   f"On that same surface, {sink.title.lower()} ({sink.location}) lets the "
                   "attacker's input change what the server executes.")
        s3 = _step(sink, "Impact", "Data is read, modified, or destroyed",
                   "With control of the query/command, the attacker can read or alter your "
                   "data — or pivot deeper into the system.")
        out.append(_finalize(
            f"unauth-exec-{door.fingerprint}-{sink.fingerprint}",
            title="Account/data takeover via unauthenticated injection",
            impact="Unauthenticated read/write of your application data",
            raw_steps=[s1, s2, s3], findings=[door, sink], reaches_impact=True,
            break_on=s1, fix_hint="require authentication on this route",
        ))
        if len(out) >= 4:
            break
    return out


def _t_xss_unleashed(ctx: "_Ctx") -> List[AttackPath]:
    """XSS that a missing/weak CSP does nothing to contain → session theft.

    Requires a browser-rendered XSS sink (not a server-only DOM write) — otherwise
    "runs in your users' browser" would be false.
    """
    xss = [f for f in ctx.by_role("browser_exec") if _is_reachable(f) and not _is_server(f)]
    csp = ctx.by_role("weak_csp")
    if not xss or not csp:
        return []
    bug = _most_severe(xss)
    gap = _most_severe(csp)
    s1 = _step(bug, "Initial Access", "Attacker delivers a script payload",
               f"An attacker gets script into a page via {bug.title.lower()} ({bug.location}).")
    # Soften when the CSP finding is itself low-confidence / hedged (e.g. headers may
    # be set in middleware) so we don't upgrade a defense-in-depth note to a certainty.
    hedged = gap.confidence == "low" or gap.reachable is False
    csp_narr = (f"No CSP is declared in {gap.location} — if it isn't set in middleware "
                "either, the browser will run the injected script unchecked."
                if hedged else
                f"{gap.title} ({gap.location}) means the browser will run that injected "
                "script — the one control that contains XSS is missing.")
    s2 = _step(gap, "Defense Evasion", "No Content-Security-Policy to contain it", csp_narr)
    s3 = _step(bug, "Credential Access", "Session/token theft in the victim's browser",
               "The script runs with your site's privileges: it can read cookies, tokens, and "
               "anything the logged-in victim can — then exfiltrate them.")
    return [_finalize(
        f"xss-unleashed-{bug.fingerprint}",
        title="Session hijack: XSS with no CSP to contain it",
        impact="Account takeover of any user who loads the page",
        raw_steps=[s1, s2, s3], findings=[bug, gap], reaches_impact=True,
        break_on=s1, fix_hint="sanitise the XSS sink",
    )]


def _t_secret_pivot(ctx: "_Ctx") -> List[AttackPath]:
    """A server-reachable read/exec primitive next to a *real, reachable* secret → pivot.

    The secret must actually be reachable by the server primitive: not proven dead
    code, not a test fixture, and not a value that's public by design (VITE_ /
    NEXT_PUBLIC_) — otherwise "a live credential in reach of that primitive" is false.
    """
    prim = [f for f in ctx.by_role("code_exec")
            if _is_server(f) and not _is_test_path(f.file)]
    secrets = [f for f in ctx.by_role("secret")
               if f.reachable is not False
               and f.rule_id not in _PUBLIC_SECRET_IDS
               and not _is_test_path(f.file)]
    if not prim or not secrets:
        return []
    p = _most_severe(prim)
    sec = _most_severe(secrets)
    # describe the primitive honestly by what it actually grants
    rid = p.rule_id
    if rid.startswith("ssrf."):
        prim_desc = "can make the server send crafted outbound requests"
        prim_title, prim_fix = "Server-side request forgery", "allow-list the outbound request target"
    elif rid.startswith("path-traversal."):
        prim_desc = "can read arbitrary files on the server"
        prim_title, prim_fix = "Server-side file read", "validate the file path against an allow-list"
    elif rid.startswith(("injection.", "sqli.", "nosqli.")) or rid == "hardening.insecure-deserialization":
        prim_desc = "can run code or queries on the server"
        prim_title, prim_fix = "Server-side code/query execution", "parameterise the query / stop running attacker-controlled input"
    else:
        prim_desc = "gives an attacker a foothold on the server"
        prim_title, prim_fix = "Server-side primitive", "close the server-side primitive"
    s1 = _step(p, "Execution", prim_title,
               f"{p.title} ({p.location}) {prim_desc}.")
    s2 = _step(sec, "Credential Access", "A real secret is sitting right there",
               f"{sec.title} ({sec.location}) puts a live credential within reach of that primitive.")
    s3 = _step(sec, "Lateral Movement", "Pivot beyond the app with stolen keys",
               "With the secret in hand, the attacker authenticates to your cloud / database / "
               "third-party services — the blast radius now extends past this app.")
    return [_finalize(
        f"secret-pivot-{p.fingerprint}-{sec.fingerprint}",
        title="Cloud/account pivot: server access → harvested secret",
        impact="Compromise of external systems the leaked credential unlocks",
        raw_steps=[s1, s2, s3], findings=[p, sec], reaches_impact=True,
        break_on=s1, fix_hint=prim_fix,
    )]


def _t_cors_token_theft(ctx: "_Ctx") -> List[AttackPath]:
    """Permissive (production) CORS + a token in web storage → cross-origin token theft."""
    # A dev-server CORS convenience setting is not a production backend exposure.
    cors = [f for f in ctx.by_role("open_cors") if f.rule_id != "vite.dev-server-cors-wildcard"]
    tokens = ctx.by_role("token_store")
    if not cors or not tokens:
        return []
    c = _most_severe(cors)
    tok = _most_severe(tokens)
    s1 = _step(c, "Initial Access", "Any origin can talk to your API with credentials",
               f"{c.title} ({c.location}) lets a malicious website make authenticated, "
               "credentialed requests to your backend from the victim's session.")
    s2 = _step(tok, "Credential Access", "The auth token is readable by JavaScript",
               f"{tok.title} ({tok.location}) keeps the session token where any script — yours, "
               "an injected one, or a malicious cross-origin response handler — can read it.")
    s3 = _step(tok, "Exfiltration", "Token is shipped to the attacker",
               "The attacker reads the token and replays it to impersonate the user.")
    return [_finalize(
        f"cors-token-{c.fingerprint}-{tok.fingerprint}",
        title="Cross-origin session token theft",
        impact="Session hijacking of authenticated users",
        raw_steps=[s1, s2, s3], findings=[c, tok], reaches_impact=True,
        break_on=s1, fix_hint="restrict CORS to a trusted allow-list of origins",
    )]


def _t_known_exploited_dep(ctx: "_Ctx") -> List[AttackPath]:
    """A dependency CVE that is actively exploited (KEV) or reachably exploitable."""
    out: List[AttackPath] = []
    for f in ctx.by_role("vuln_dep"):
        kev = _kev(f)
        vex = f.metadata.get("vex_state")
        reachable_vuln = f.reachable is True or vex == "exploitable"
        if not (kev or reachable_vuln):
            continue  # skip not_affected / unreachable noise — that's the whole point
        pkg = f.metadata.get("package", "a dependency")
        adv = f.metadata.get("advisory_id", "a known CVE")
        patched = f.metadata.get("patched")
        s1 = _step(f, "Initial Access", "Exposed dependency with a public exploit",
                   (f"You ship `{pkg}` affected by {adv}"
                    + (" — and it is being actively exploited in the wild (CISA KEV)."
                       if kev else ", reachable from code you actually call.")))
        s2 = _step(f, "Execution", "Attacker triggers the known vulnerability",
                   "Public exploit code exists; the attacker runs it against your deployment.")
        fix = f"upgrade {pkg} to {patched}" if patched else f"upgrade or remove {pkg}"
        out.append(_finalize(
            f"kev-dep-{f.fingerprint}",
            title=f"Exploitation of {pkg} via {adv}"
                  + ("  (actively exploited)" if kev else ""),
            impact="Compromise via a publicly-known dependency exploit",
            raw_steps=[s1, s2], findings=[f], reaches_impact=True,
            break_on=s1, fix_hint=fix,
        ))
    return out[:4]


def _t_supply_chain(ctx: "_Ctx") -> List[AttackPath]:
    """An install-time / integrity supply-chain compromise runs before your app does."""
    out: List[AttackPath] = []
    for f in ctx.by_role("supply_foothold"):
        if f.effective_severity.rank < Severity.HIGH.rank:
            continue  # missing-integrity etc. is a gap, not an active foothold
        s1 = _step(f, "Initial Access", "Malicious code arrives via a dependency",
                   f"{f.title} ({f.location}) — {f.message or 'a dependency carries attacker code.'}")
        s2 = _step(f, "Execution", "It runs at install time, before your app starts",
                   "npm runs lifecycle scripts on `npm install` / CI — this executes on your "
                   "build server or developer machine with no app code involved.")
        out.append(_finalize(
            f"supply-{f.fingerprint}",
            title="Build/CI compromise via a malicious dependency",
            impact="Code execution on your build server, CI, or developers' machines",
            raw_steps=[s1, s2], findings=[f], reaches_impact=True,
            break_on=s1, fix_hint="remove or pin this dependency and audit the script",
        ))
    return out[:4]


_TEMPLATES = [
    _t_taint_flow,
    _t_unauth_exec,
    _t_xss_unleashed,
    _t_secret_pivot,
    _t_cors_token_theft,
    _t_known_exploited_dep,
    _t_supply_chain,
]


# ── context + driver ──────────────────────────────────────────────────────────

class _Ctx:
    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings
        self._by_role: Dict[str, List[Finding]] = {}
        for f in findings:
            for role in _roles(f):
                self._by_role.setdefault(role, []).append(f)

    def by_role(self, role: str) -> List[Finding]:
        return self._by_role.get(role, [])


def synthesize(findings: List[Finding], *, max_paths: int = 12) -> List[AttackPath]:
    """Compose findings into ranked, de-duplicated attack paths.

    Conservative by design: never raises, returns ``[]`` when nothing chains. Paths
    that are a strict subset of a richer path are dropped, and results are ranked by
    score (then step count) with ``max_paths`` kept.
    """
    if not findings:
        return []
    try:
        ctx = _Ctx(findings)
        candidates: List[AttackPath] = []
        for template in _TEMPLATES:
            try:
                candidates.extend(template(ctx))
            except Exception:  # noqa: BLE001 — one bad template never sinks the scan
                continue
        return _dedupe_and_rank(candidates, max_paths)
    except Exception:  # noqa: BLE001
        return []


def _dedupe_and_rank(paths: List[AttackPath], max_paths: int) -> List[AttackPath]:
    # strongest first so subset-suppression keeps the richer chain
    paths.sort(key=lambda p: (-p.score, -len(p.steps)))
    kept: List[AttackPath] = []
    kept_sets: List[frozenset] = []
    seen_sigs: Set[tuple] = set()
    for p in paths:
        fps = p.fingerprint_set
        if not fps:
            continue
        if any(fps <= existing for existing in kept_sets):
            continue  # this path's findings are already covered by a richer one
        # also drop paths that would RENDER identically (same title + step locations),
        # so a viewer never sees two copies of the same story.
        sig = (p.title,) + tuple((s.tactic, s.title, s.file, s.line) for s in p.steps)
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        kept.append(p)
        kept_sets.append(fps)
    # renumber ids stably (path-1 strongest) for human reference
    for i, p in enumerate(kept[:max_paths], start=1):
        p.id = f"path-{i}"
    return kept[:max_paths]

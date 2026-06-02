"""Drive AI explanations over a set of findings.

Privacy-first defaults:
  - If the user asks for AI but names no provider, we default to **ollama** (local,
    nothing leaves the machine).
  - For remote providers we print a clear notice of exactly what will be sent and
    redact secrets from code first (unless --no-redact). ``--no-external`` hard-blocks
    any remote provider.
  - This step is best-effort: if the provider is unavailable we explain why and fall
    back to the offline explanations every finding already carries. It never crashes a scan.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from rich.console import Console
from rich.markup import escape

from ..core.config import Config
from ..core.finding import Finding
from .providers import Provider, ProviderError, get_provider, would_reach_network
from .redact import redact

err = Console(stderr=True)

# Cap how many findings we send, to keep cost/time bounded for a beginner.
_MAX_EXPLAIN = 25

_SYSTEM = (
    "You are a friendly application-security mentor helping a developer who is NOT a "
    "security expert. Given one finding from a static scan of a Next.js/React/Vite app, "
    "explain in plain English (1) in 2-3 sentences why this specific code is risky, and "
    "(2) the concrete fix for THIS code, with a short corrected snippet. Be encouraging, "
    "specific, and concise. Do not invent issues beyond what is shown."
)


def explain_findings(findings: List[Finding], config: Config) -> None:
    """Populate ``finding.ai_explanation`` in place for up to ``_MAX_EXPLAIN`` findings."""
    if not findings:
        return

    provider_name = config.ai_provider or "ollama"

    if would_reach_network(provider_name) and config.no_external:
        err.print(f"[yellow]--no-external is set; skipping provider '{provider_name}' (would "
                  "reach the network). Use a local model (ollama on a loopback OLLAMA_HOST).[/yellow]")
        return

    try:
        provider = get_provider(provider_name)
    except ProviderError as exc:
        err.print(f"[yellow]{escape(str(exc))}[/yellow]")
        return

    ok, reason = provider.check()
    if not ok:
        err.print(f"[yellow]AI explanations unavailable: {escape(reason)}[/yellow]")
        err.print("[dim]Falling back to the built-in offline explanations (already shown).[/dim]")
        return

    targets = findings[:_MAX_EXPLAIN]
    redacting = would_reach_network(provider_name) and config.ai_redact
    _notice(provider, reason, len(targets), redacting, config)

    def _explain_one(finding: Finding) -> None:
        snippet = redact(finding.code_snippet) if redacting else finding.code_snippet
        text = provider.complete(_SYSTEM, _prompt(finding, snippet))
        if text:
            finding.ai_explanation = text

    # Probe with the first finding. If the very first model call fails, it's almost
    # always a systemic problem (model not pulled, bad key) — report it ONCE and
    # fall back to offline, instead of emitting one error per finding.
    try:
        _explain_one(targets[0])
    except ProviderError as exc:
        err.print(f"[yellow]AI explanation failed: {escape(str(exc))}[/yellow]")
        if provider.is_local:
            err.print(f"[dim]Is the model pulled?  Try:  ollama pull {escape(getattr(provider, 'model', ''))}[/dim]")
        err.print("[dim]Falling back to the built-in offline explanations (already shown).[/dim]")
        return

    rest = targets[1:]
    if not rest:
        return
    # Local models are usually serial-friendly; remote APIs benefit from a little
    # concurrency. Keep it modest so we never hammer an endpoint.
    workers = 1 if provider.is_local else 4
    failures = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_explain_one, f): f for f in rest}
        for fut in as_completed(futures):
            try:
                fut.result()
            except ProviderError:
                failures += 1
    if failures:
        err.print(f"[dim]· {failures} finding(s) could not be explained by AI; offline guidance shown for those.[/dim]")


def _prompt(finding: Finding, snippet: str) -> str:
    parts = [
        f"Rule: {finding.rule_id} — {finding.title}",
        f"Severity: {finding.effective_severity.value}",
        f"File: {finding.location}",
    ]
    if finding.cwe:
        parts.append(f"Weakness: {finding.cwe}")
    if snippet:
        parts.append(f"Code:\n```\n{snippet}\n```")
    if finding.taint_flow:
        flow = " -> ".join(f"{s.kind}:{s.label}" for s in finding.taint_flow)
        parts.append(f"Tainted data flow: {flow}")
    parts.append("Explain why this is risky here and how to fix it.")
    return "\n".join(parts)


def _notice(provider: Provider, reason: str, count: int, redacting: bool, config: Config) -> None:
    if provider.is_local:
        err.print(f"[dim]🔒 Explaining {count} finding(s) with a local model ({escape(reason)}). "
                  "Nothing leaves your machine.[/dim]")
        return
    redact_note = "secrets redacted" if redacting else "[red]code sent UN-redacted (--no-redact)[/red]"
    err.print(
        f"[yellow]☁  Sending {count} finding(s) with code context to {escape(reason)} — {redact_note}.[/yellow]\n"
        "[dim]   This calls an external API. Use --ai-provider ollama to keep everything local, "
        "or --no-external to disable remote calls.[/dim]"
    )

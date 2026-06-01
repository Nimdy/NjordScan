"""Rich terminal reporter.

This is the experience a non-security developer actually sees, so it is built to
*teach*: each finding shows the risky code, a plain-English "why this matters",
an actionable fix, and a secure example to copy. Verbosity adapts so a clean
project gets a friendly all-clear and a noisy one stays scannable.
"""

from __future__ import annotations

from typing import List

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule as HRule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from ..core.finding import Finding
from ..core.orchestrator import ScanResult
from ..core.severity import Severity


def render_terminal(result: ScanResult, console: Console, *, verbose: bool = False, show_fix: bool = True) -> None:
    console.print()
    _header(result, console)

    if not result.findings:
        console.print(Panel(
            Text("No security issues found. \n\nThat's great — but no scanner catches everything. "
                 "Keep your dependencies updated and review anything that handles user input.",
                 justify="left"),
            title="✅ All clear", border_style="green", padding=(1, 2),
        ))
        _footer(result, console)
        return

    _summary_table(result, console)
    console.print()

    for idx, finding in enumerate(result.findings, start=1):
        _render_finding(idx, finding, console, show_fix=show_fix)

    _footer(result, console)


def _header(result: ScanResult, console: Console) -> None:
    p = result.project
    fw = p.framework if p.framework != "unknown" else "no framework detected"
    title = Text("🛡  NjordScan", style="bold cyan")
    meta = Text(f"  ·  {fw}  ·  {result.files_scanned} files  ·  {result.duration_s:.2f}s", style="dim")
    console.print(Text.assemble(title, meta))
    console.print(Text(str(p.root), style="dim"))


def _summary_table(result: ScanResult, console: Console) -> None:
    counts = result.counts
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts[sev]
        if n:
            table.add_row(Text(f"{sev.emoji} {sev.value.title()}", style=sev.color), str(n))
    table.add_row(Text("Total", style="bold"), Text(str(result.total), style="bold"))
    console.print(Panel(table, title="Summary", border_style="cyan", expand=False, padding=(0, 2)))


def _render_finding(idx: int, finding: Finding, console: Console, *, show_fix: bool) -> None:
    sev = finding.effective_severity
    heading = Text.assemble(
        (f"{sev.emoji} ", ""),
        (f"[{sev.value.upper()}] ", sev.color),
        (finding.title, "bold"),
    )
    sub = Text(f"{finding.location}", style="dim")
    tags = []
    if finding.cwe:
        tags.append(finding.cwe)
    if finding.owasp:
        tags.append(finding.owasp)
    if finding.attack:
        tags.append("ATT&CK " + ", ".join(finding.attack))
    tags.append(f"confidence: {finding.confidence}")
    tag_text = Text("  ·  ".join(tags), style="dim italic")

    blocks: List = [sub, tag_text]
    if finding.reachable is True:
        reach = finding.metadata.get("reachability", {})
        where = reach.get("entrypoint")
        scope = reach.get("kind", "")
        scope_txt = f" ({scope}-side)" if scope in ("server", "client") else ""
        line = Text(f"\n🎯 Reachable{scope_txt}", style="bold red")
        if where:
            line.append(f" from {where}", style="dim")
        blocks.append(line)
    elif finding.reachable is False:
        blocks.append(Text("\n○ Not reachable from a known entrypoint (lower priority)", style="dim"))
    if finding.message:
        blocks.append(Text(f"\n{finding.message}"))

    if finding.code_snippet:
        blocks.append(Text("\nFound here:", style="bold"))
        blocks.append(_code(finding.code_snippet, finding.file))

    if finding.taint_flow:
        blocks.append(Text("\nData flow (untrusted input → dangerous use):", style="bold"))
        flow = Text()
        for i, step in enumerate(finding.taint_flow):
            arrow = "" if i == 0 else "   ↓\n"
            flow.append(arrow)
            flow.append(f"   {step.kind:>11}: ", style="dim")
            flow.append(f"{step.label} ", style="yellow")
            flow.append(f"({step.file}:{step.line})\n", style="dim")
        blocks.append(flow)

    # --brief (show_fix=False) hides all the explanatory detail for a terse list;
    # the AI review (if explicitly requested) is always shown.
    if show_fix and finding.why:
        blocks.append(Text("\n💡 Why this matters", style="bold yellow"))
        blocks.append(Text(finding.why))

    if show_fix and finding.fix:
        blocks.append(Text("\n🛠  How to fix it", style="bold green"))
        blocks.append(Text(finding.fix))
        if finding.secure_example:
            blocks.append(_code(finding.secure_example, finding.file, theme_ok=True))

    if finding.ai_explanation:
        blocks.append(Text("\n🤖 AI review", style="bold magenta"))
        blocks.append(Text(finding.ai_explanation))

    if show_fix and finding.references:
        refs = Text("\n📚 Learn more\n", style="bold")
        for url in finding.references[:3]:
            refs.append(f"   • {url}\n", style="blue underline")
        blocks.append(refs)

    console.print(Panel(
        Group(*blocks),
        title=Text.assemble((f" {idx}. ", "dim"), heading),
        title_align="left",
        border_style=sev.color.split()[-1],
        padding=(1, 2),
    ))
    console.print()


def _code(snippet: str, filename: str, *, theme_ok: bool = False) -> Syntax:
    lexer = "tsx" if filename.endswith((".tsx", ".jsx")) else (
        "typescript" if filename.endswith(".ts") else "javascript"
    )
    if filename.endswith((".json",)):
        lexer = "json"
    return Syntax(
        snippet, lexer, theme="ansi_dark", word_wrap=True,
        background_color="default", padding=(0, 2),
    )


def _footer(result: ScanResult, console: Console) -> None:
    console.print(HRule(style="dim"))
    if result.errors:
        console.print(Text(f"⚠ {len(result.errors)} detector(s) reported errors (run with -v for details).",
                           style="yellow"))
    tip = Text.assemble(
        ("Tip: ", "bold"),
        ("run ", "dim"),
        ("njordscan explain <rule-id>", "cyan"),
        (" for a deeper walk-through, or ", "dim"),
        ("--explain-with-ai", "cyan"),
        (" for an AI-assisted review.", "dim"),
    )
    console.print(tip)

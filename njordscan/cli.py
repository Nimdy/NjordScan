"""NjordScan command-line interface.

Design goals for a non-expert audience:
  - the happy path is one command: ``njordscan scan .``
  - exit codes are correct and predictable (great for CI without ceremony)
  - nothing blocks on interactive prompts; nothing phones home by default
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from . import __version__
from .core.baseline import Baseline, write_baseline
from .core.config import Config
from .core.configfile import FileConfig, find_config, load_config_file
from .core.orchestrator import Orchestrator, ScanResult
from .core.severity import Severity
from .knowledge import all_rules, get_rule
from .report import available_formats, render_terminal, render_to_string

console = Console()
err_console = Console(stderr=True)

_SEVERITY_CHOICES = [s.value for s in Severity]

# Exit codes (documented, stable):
EXIT_OK = 0           # scan ran; no findings at/above --fail-on (or no gate set)
EXIT_FINDINGS = 1     # scan ran; findings met the --fail-on threshold
EXIT_ERROR = 2        # scan could not run (bad path, internal error)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="njordscan")
def cli() -> None:
    """🛡  NjordScan — security scanning for Next.js, React & Vite, explained in plain English."""


@cli.command()
@click.argument("target", type=click.Path(path_type=Path), default=".")
@click.option("--mode", type=click.Choice(["quick", "standard", "deep"]), default="standard",
              help="Scan depth. 'quick' = fast static checks; 'deep' = everything.")
@click.option("--format", "fmt", type=click.Choice(available_formats()), default="terminal",
              help="Output format.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Write the report to a file (for json/sarif).")
@click.option("--min-severity", type=click.Choice(_SEVERITY_CHOICES), default="info",
              help="Hide findings below this severity.")
@click.option("--fail-on", type=click.Choice(_SEVERITY_CHOICES), default=None,
              help="Exit with code 1 if any finding is at or above this severity (for CI).")
@click.option("--only", "only", multiple=True, help="Run only these detectors (repeatable).")
@click.option("--skip", "skip", multiple=True, help="Skip these detectors (repeatable).")
@click.option("--ignore", "ignore", multiple=True, help="Extra ignore glob(s) (repeatable).")
@click.option("--brief", is_flag=True, help="Hide the 'why/how to fix' detail (terse output).")
@click.option("--fix", "do_fix", is_flag=True, help="Apply safe, additive autofixes for supported rules.")
@click.option("--dry-run", is_flag=True, help="With --fix: preview the diff without writing changes.")
@click.option("--explain-with-ai", is_flag=True,
              help="Add AI-written explanations (opt-in; see --ai-provider).")
@click.option("--ai-provider", type=click.Choice(["ollama", "claude", "openai"]), default=None,
              help="Which AI backend to use with --explain-with-ai.")
@click.option("--no-redact", is_flag=True,
              help="Send unredacted code to the AI provider (off by default).")
@click.option("--baseline", type=click.Path(path_type=Path), default=None,
              help="Baseline file: hide known findings and only fail on NEW ones.")
@click.option("--update-baseline", is_flag=True,
              help="Write the current findings to the --baseline file and exit.")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None,
              help="Path to a .njordscan.yml config file (auto-detected by default).")
@click.option("--no-config", is_flag=True, help="Ignore any .njordscan.yml config file.")
@click.option("-v", "--verbose", is_flag=True, help="Show detector errors and extra detail.")
@click.option("--quiet", is_flag=True, help="Only print the summary line.")
def scan(
    target: Path, mode: str, fmt: str, output: Optional[Path], min_severity: str,
    fail_on: Optional[str], only: tuple, skip: tuple, ignore: tuple, brief: bool,
    do_fix: bool, dry_run: bool,
    explain_with_ai: bool, ai_provider: Optional[str], no_redact: bool,
    baseline: Optional[Path], update_baseline: bool,
    config_path: Optional[Path], no_config: bool,
    verbose: bool, quiet: bool,
) -> None:
    """🔍 Scan a project directory for security issues.

    TARGET defaults to the current directory.
    """
    if not target.exists():
        err_console.print(f"[red]✗ Path does not exist:[/red] {target}")
        sys.exit(EXIT_ERROR)
    if not target.is_dir():
        err_console.print(f"[red]✗ Target must be a directory:[/red] {target}")
        sys.exit(EXIT_ERROR)

    file_cfg = _resolve_file_config(target, config_path, no_config, verbose)
    only_ids = _split_csv(only)
    skip_ids = _split_csv(skip)

    config = Config(
        target=target,
        mode=mode,
        min_severity=Severity.from_str(min_severity if min_severity != "info" else (file_cfg.min_severity or "info")),
        fail_on=Severity.from_str(fail_on) if fail_on else (Severity.from_str(file_cfg.fail_on) if file_cfg.fail_on else None),
        extra_ignores=[*ignore, *file_cfg.ignore],
        only_detectors=only_ids or file_cfg.only_detectors,
        skip_detectors=[*skip_ids, *file_cfg.skip_detectors],
        disabled_rules=set(file_cfg.disable_rules),
        severity_overrides={k: Severity.from_str(str(v)) for k, v in file_cfg.severity.items()},
        explain_with_ai=explain_with_ai,
        ai_provider=ai_provider or (file_cfg.ai_provider if explain_with_ai else None),
        ai_redact=not no_redact,
    )

    try:
        result: ScanResult = asyncio.run(Orchestrator(config).run())
    except (FileNotFoundError, NotADirectoryError) as exc:
        err_console.print(f"[red]✗ {exc}[/red]")
        sys.exit(EXIT_ERROR)
    except Exception as exc:  # noqa: BLE001 — surface unexpected errors cleanly, not as a traceback
        err_console.print(f"[red]✗ Scan failed:[/red] {exc!r}")
        if verbose:
            console.print_exception()
        sys.exit(EXIT_ERROR)

    # --- baseline handling ---
    baseline_path = baseline or (Path(file_cfg.baseline) if file_cfg.baseline else None)
    if baseline_path and not baseline_path.is_absolute():
        baseline_path = target / baseline_path

    if update_baseline:
        if not baseline_path:
            err_console.print("[red]✗ --update-baseline needs --baseline PATH (or 'baseline:' in config).[/red]")
            sys.exit(EXIT_ERROR)
        n = write_baseline(baseline_path, result.findings)
        console.print(f"[green]✓[/green] Baseline updated: {n} finding(s) recorded in {baseline_path}")
        sys.exit(EXIT_OK)

    hidden = 0
    if baseline_path and baseline_path.exists():
        new, known = Baseline.load(baseline_path).partition(result.findings)
        hidden = len(known)
        result.findings = new

    if explain_with_ai:
        _apply_ai_explanations(result, config)

    _emit(result, fmt, output, verbose=verbose, quiet=quiet, show_fix=not brief)
    if hidden and not quiet and fmt == "terminal":
        console.print(f"[dim]({hidden} known finding(s) hidden by baseline.)[/dim]")

    if do_fix:
        _run_autofix(result, config, dry_run=dry_run)

    if config.fail_on and result.exceeds(config.fail_on):
        sys.exit(EXIT_FINDINGS)
    sys.exit(EXIT_OK)


def _run_autofix(result: ScanResult, config: Config, *, dry_run: bool) -> None:
    from .fix import apply_fixes

    report = apply_fixes(result, result.project, dry_run=dry_run)
    if not report.applied:
        console.print("[dim]No auto-fixable findings (safe fixes only).[/dim]")
        return
    verb = "Would apply" if dry_run else "Applied"
    console.print(f"\n[bold green]🔧 {verb} {report.count} safe fix(es)[/bold green] "
                  f"across {len(set(report.files_changed))} file(s):")
    for fix in report.applied:
        console.print(f"  [green]✓[/green] {fix.file}:{fix.line or ''} — {fix.description}")
    if dry_run:
        for name, diff in report.diffs.items():
            if diff:
                from rich.syntax import Syntax
                console.print(Syntax(diff, "diff", theme="ansi_dark", background_color="default"))
        console.print("[dim]Dry run — no files were modified. Re-run with --fix (no --dry-run) to apply.[/dim]")


def _split_csv(values: tuple) -> List[str]:
    """Accept both repeated flags and comma-separated values (--only a,b)."""
    out: List[str] = []
    for v in values:
        out.extend(part.strip() for part in str(v).split(",") if part.strip())
    return out


def _resolve_file_config(target: Path, config_path: Optional[Path], no_config: bool, verbose: bool) -> FileConfig:
    if no_config:
        return FileConfig()
    path = config_path or find_config(target)
    if path and path.is_file():
        if verbose:
            console.print(f"[dim]Using config: {path}[/dim]")
        return load_config_file(path)
    return FileConfig()


def _emit(result: ScanResult, fmt: str, output: Optional[Path], *,
          verbose: bool, quiet: bool, show_fix: bool) -> None:
    if fmt == "terminal":
        if quiet:
            _print_summary_line(result)
        else:
            render_terminal(result, console, verbose=verbose, show_fix=show_fix)
        if verbose and result.errors:
            for e in result.errors:
                err_console.print(f"[yellow]· {e}[/yellow]")
        return

    rendered = render_to_string(result, fmt)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]✓[/green] {fmt.upper()} report written to {output}")
    else:
        click.echo(rendered)


def _print_summary_line(result: ScanResult) -> None:
    c = result.counts
    console.print(
        f"NjordScan: {result.total} issue(s) — "
        f"{c[Severity.CRITICAL]} critical, {c[Severity.HIGH]} high, "
        f"{c[Severity.MEDIUM]} medium, {c[Severity.LOW]} low."
    )


def _apply_ai_explanations(result: ScanResult, config: Config) -> None:
    """Best-effort AI enrichment. Never fails the scan; warns if unavailable."""
    try:
        from .explain import explain_findings
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[yellow]AI explanations unavailable: {exc}[/yellow]")
        return
    try:
        explain_findings(result.findings, config)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[yellow]AI explanation step skipped: {exc}[/yellow]")


@cli.command()
@click.argument("rule_id", required=False)
def explain(rule_id: Optional[str]) -> None:
    """💡 Explain a rule in depth (why it matters, how to fix it).

    Run without an argument to list every rule NjordScan knows about.
    """
    if not rule_id:
        _list_rules()
        return
    rule = get_rule(rule_id)
    if rule is None:
        err_console.print(f"[red]Unknown rule:[/red] {rule_id}")
        err_console.print("Run [cyan]njordscan explain[/cyan] to list all rules.")
        sys.exit(EXIT_ERROR)

    from rich.panel import Panel
    from rich.text import Text
    body = Text()
    body.append("Why this matters\n", style="bold yellow")
    body.append(rule.why + "\n\n")
    body.append("How to fix it\n", style="bold green")
    body.append(rule.fix + "\n")
    if rule.secure_example:
        body.append("\nSecure example:\n", style="bold")
        body.append(rule.secure_example + "\n")
    meta = "  ·  ".join(filter(None, [rule.cwe, rule.owasp, f"severity: {rule.severity.value}"]))
    if meta:
        body.append(f"\n{meta}\n", style="dim italic")
    for url in rule.references:
        body.append(f"• {url}\n", style="blue underline")
    console.print(Panel(body, title=f"{rule.severity.emoji} {rule.title}  [{rule.id}]",
                        title_align="left", border_style=rule.severity.color.split()[-1], padding=(1, 2)))


def _list_rules() -> None:
    from rich.table import Table
    table = Table(title="NjordScan rules", header_style="bold cyan")
    table.add_column("Rule ID")
    table.add_column("Severity")
    table.add_column("Title")
    for rule in sorted(all_rules(), key=lambda r: (-r.severity.rank, r.id)):
        table.add_row(rule.id, f"{rule.severity.emoji} {rule.severity.value}", rule.title)
    console.print(table)


@cli.command()
@click.argument("directory", type=click.Path(path_type=Path), default=".")
@click.option("--force", is_flag=True, help="Overwrite an existing config file.")
def init(directory: Path, force: bool) -> None:
    """🧩 Create a starter .njordscan.yml in the given directory."""
    from .core.configfile import STARTER

    dest = directory / ".njordscan.yml"
    if dest.exists() and not force:
        err_console.print(f"[yellow]{dest} already exists.[/yellow] Use --force to overwrite.")
        sys.exit(EXIT_ERROR)
    dest.write_text(STARTER, encoding="utf-8")
    console.print(f"[green]✓[/green] Wrote {dest}")
    console.print("Edit it to fit your project, then run [cyan]njordscan scan .[/cyan]")


@cli.command()
@click.argument("target", type=click.Path(path_type=Path), default=".")
@click.option("--quiet", is_flag=True, help="Less output.")
def update(target: Path, quiet: bool) -> None:
    """🔄 Refresh dependency advisories from OSV.dev (keeps the CVE data current)."""
    from .update import POPULAR_NPM, refresh

    names = list(POPULAR_NPM)
    pkg = target / "package.json" if target.is_dir() else None
    if pkg and pkg.exists():
        try:
            import json as _json
            data = _json.loads(pkg.read_text(encoding="utf-8"))
            for sect in ("dependencies", "devDependencies"):
                names.extend((data.get(sect) or {}).keys())
        except Exception:  # noqa: BLE001
            pass

    console.print(f"[cyan]Refreshing advisories[/cyan] for {len(set(names))} packages from OSV.dev…")
    try:
        if quiet:
            result = refresh(names)
        else:
            with console.status("[cyan]Querying OSV.dev…[/cyan]") as status:
                result = refresh(names, progress=lambda n: status.update(f"[cyan]OSV.dev[/cyan] · {n}"))
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]✗ Update failed:[/red] {exc!r}")
        sys.exit(EXIT_ERROR)

    console.print(
        f"[green]✓[/green] {result['total_advisories']} advisories for "
        f"{result['packages_with_advisories']} packages → {result['path']}"
    )
    if result["errors"] and not quiet:
        console.print(f"[yellow]{len(result['errors'])} package(s) could not be fetched "
                      "(offline or rate-limited).[/yellow]")


@cli.command()
def doctor() -> None:
    """🩺 Show what's installed and working (detectors, rules, advisories, AI)."""
    import sys as _sys
    from rich.table import Table

    from .core.paths import user_advisories_path
    from .detectors import load_detectors

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("NjordScan", f"[cyan]v{__version__}[/cyan]")
    t.add_row("Python", _sys.version.split()[0])
    detectors = load_detectors()
    t.add_row("Detectors", ", ".join(d.id for d in detectors) or "[red]none[/red]")
    t.add_row("Rules", str(len(all_rules())))
    try:
        from .detectors.pattern_engine import _load_patterns
        t.add_row("Patterns", str(len(_load_patterns())))
    except Exception:  # noqa: BLE001
        pass

    # advisory freshness
    seed = "shipped seed"
    cache = user_advisories_path()
    if cache.exists():
        try:
            import json as _json
            meta = _json.loads(cache.read_text()).get("_meta", {})
            seed += f" + user cache ({meta.get('packages_queried', '?')} pkgs from {meta.get('source', 'osv')})"
        except Exception:  # noqa: BLE001
            pass
    else:
        seed += " (run 'njordscan update' to refresh from OSV.dev)"
    t.add_row("Advisories", seed)

    # taint engine availability
    try:
        import tree_sitter  # noqa: F401
        t.add_row("Taint engine", "[green]tree-sitter available[/green]")
    except ImportError:
        t.add_row("Taint engine", "[yellow]tree-sitter missing (taint disabled)[/yellow]")

    # AI providers
    ai_rows = []
    try:
        import httpx  # noqa: F401
        ai_rows.append("httpx installed")
    except ImportError:
        ai_rows.append(r"httpx missing (pip install 'njordscan\[ai]')")  # escape [ai] for rich
    import os as _os
    ai_rows.append("ANTHROPIC_API_KEY set" if _os.getenv("ANTHROPIC_API_KEY") else "no Anthropic key")
    ai_rows.append("OPENAI_API_KEY set" if _os.getenv("OPENAI_API_KEY") else "no OpenAI key")
    t.add_row("AI explain", "; ".join(ai_rows))

    console.print(t)


@cli.command()
def version() -> None:
    """📋 Show version information."""
    console.print(f"NjordScan [bold cyan]v{__version__}[/bold cyan]")
    console.print("Security scanning for Next.js, React & Vite — explained in plain English.")


def main(argv: Optional[List[str]] = None) -> None:
    cli.main(args=argv, standalone_mode=True)


if __name__ == "__main__":
    main()

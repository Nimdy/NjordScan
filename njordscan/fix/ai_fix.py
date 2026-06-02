"""Agentic AI fix-and-verify.

Mechanical autofix (``--fix``) only covers a handful of provably-safe edits. This
goes further: for code findings an LLM can plausibly patch, it

  1. asks the model for a corrected version of the file,
  2. applies it to a throwaway copy of the project,
  3. **re-scans** that copy, and
  4. keeps the fix ONLY if the targeted issue is gone AND no new issue appeared.

So the AI never gets the last word — NjordScan verifies the patch actually worked
before showing or applying it. Opt-in (needs an AI provider) and shows a diff.
"""

from __future__ import annotations

import asyncio
import difflib
import re
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..core.config import Config
from ..core.finding import Finding
from ..core.orchestrator import Orchestrator, ScanResult

# Detectors whose findings are a single-file code edit an LLM can attempt.
_FIXABLE_DETECTORS = {"static", "taint", "patterns", "configs"}
_MAX_FILES = 8
_MAX_ATTEMPTS = 3   # agentic retries per file: propose -> verify -> feedback -> retry

_SYSTEM = (
    "You are a senior application-security engineer. You are given the full contents of one "
    "source file and one or more security findings in it. Return the COMPLETE corrected file "
    "that fixes ONLY those security issues while preserving all other behavior and style. "
    "Do not add commentary. Output only the corrected file inside a single code block."
)


@dataclass
class AiFix:
    file: str
    rules_fixed: List[str]
    diff: str
    attempts: int = 1


@dataclass
class AiFixReport:
    applied: List[AiFix] = field(default_factory=list)
    unverified: List[str] = field(default_factory=list)
    dry_run: bool = False
    provider: str = ""
    error: Optional[str] = None

    @property
    def count(self) -> int:
        return len(self.applied)


def ai_fix(result: ScanResult, config: Config, *, dry_run: bool, provider=None) -> AiFixReport:
    report = AiFixReport(dry_run=dry_run)

    provider_name = getattr(provider, "name", None) or config.ai_provider or "ollama"

    # Privacy gate. Unlike --explain (which sends a small, REDACTED snippet and gets
    # text back), --ai-fix must send the FULL file contents to the model to receive a
    # working corrected file — so it cannot redact without corrupting the output. We
    # therefore honor --no-external as a HARD BLOCK for anything that would leave the
    # machine, and warn loudly before any egress otherwise. The egress check fails
    # CLOSED: remote providers, ollama pointed off-box via OLLAMA_HOST, and any passed
    # provider that doesn't declare itself local all count as egress.
    egress = _would_egress(provider, provider_name)
    if egress and config.no_external:
        report.provider = provider_name
        report.error = (
            f"--no-external is set, so --ai-fix refuses to send source code off this machine "
            f"(provider '{provider_name}'). A fix cannot be redacted — the model must return your "
            f"actual file — so use a LOCAL model (ollama on a loopback OLLAMA_HOST) to proceed."
        )
        return report

    if provider is None:
        from ..explain.providers import ProviderError, get_provider
        try:
            provider = get_provider(provider_name)
        except ProviderError as exc:
            report.error = str(exc)
            return report
    report.provider = getattr(provider, "name", "ai")
    ok, reason = provider.check()
    if not ok:
        report.error = reason
        return report

    if egress:
        _remote_egress_notice(provider_name, _MAX_FILES)

    project = result.project
    code_exts = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
    by_file: Dict[str, List[Finding]] = {}
    for f in result.findings:
        if f.detector in _FIXABLE_DETECTORS and f.file.endswith(code_exts):
            by_file.setdefault(f.file, []).append(f)
    # prioritize reachable files, cap the count
    files = sorted(by_file, key=lambda rel: 0 if any(x.reachable for x in by_file[rel]) else 1)[:_MAX_FILES]
    if not files:
        return report

    with tempfile.TemporaryDirectory() as tmp:
        tmproot = Path(tmp) / "proj"
        shutil.copytree(project.root, tmproot,
                        ignore=shutil.ignore_patterns(".git", ".venv", "node_modules", ".njordscan", "dist", "build"))
        scan_cfg = Config(target=tmproot, reachability=False, skip_detectors=["dependencies", "runtime"])

        for rel in files:
            src = project.root / rel
            try:
                original = src.read_text(encoding="utf-8")
            except OSError:
                continue
            before_rules = Counter(f.rule_id for f in by_file[rel])
            tfile = tmproot / rel

            # Agentic loop: propose -> verify by re-scan -> feed failures back -> retry.
            candidate: Optional[str] = None
            still: List[str] = []
            introduced: List[str] = []
            verified = False
            for attempt in range(1, _MAX_ATTEMPTS + 1):
                prompt = (_prompt(rel, original, by_file[rel]) if candidate is None
                          else _retry_prompt(rel, candidate, still, introduced))
                try:
                    corrected = _strip_fences(provider.complete(_SYSTEM, prompt))
                except Exception:  # noqa: BLE001 - a provider/network failure mid-run must
                    break          # not crash the whole scan; leave this file unverified
                if not corrected or corrected.strip() == original.strip():
                    break
                tfile.write_text(corrected, encoding="utf-8")
                try:
                    rescan = _scan_now(scan_cfg)
                except Exception:  # noqa: BLE001
                    break

                after = Counter(f.rule_id for f in rescan.findings if f.file == rel)
                # only ``rel`` changed, so only its findings can have moved
                still = [r for r in before_rules if after[r] >= before_rules[r]]
                introduced = [r for r in after if after[r] > before_rules.get(r, 0)]
                if not still and not introduced:
                    report.applied.append(AiFix(rel, sorted(before_rules),
                                                _diff(original, corrected, rel), attempts=attempt))
                    if not dry_run:
                        src.write_text(corrected, encoding="utf-8")
                    verified = True
                    break  # keep the verified fix in the temp tree for later files
                candidate = corrected

            if not verified:
                tfile.write_text(original, encoding="utf-8")
                report.unverified.append(rel)

    return report


def _would_egress(provider, provider_name: str) -> bool:
    """True if running --ai-fix with this provider would send source OFF this machine.

    Fails CLOSED: a remote provider, ollama pointed at a non-loopback OLLAMA_HOST, or
    any passed-in provider object that does not explicitly declare ``is_local`` — an
    unknown/unregistered provider name is treated as remote, never assumed local.
    """
    from ..explain.providers import would_reach_network

    if would_reach_network(provider_name):
        return True
    if provider is not None and not getattr(provider, "is_local", False):
        return True
    return False


def _remote_egress_notice(provider_name: str, max_files: int) -> None:
    """Warn, before any egress, that --ai-fix sends full file contents un-redacted."""
    try:
        from rich.console import Console

        Console(stderr=True).print(
            f"[yellow]☁  --ai-fix is sending the FULL contents of up to {max_files} file(s) to the "
            f"remote provider '{escape_name(provider_name)}' UN-redacted — a fix must preserve your "
            f"code, so it cannot be masked. Use --ai-provider ollama (local) or --no-external to keep "
            f"code on your machine.[/yellow]"
        )
    except Exception:  # pragma: no cover - a notice must never break the fix path
        pass


def escape_name(name: str) -> str:
    return name.replace("[", "").replace("]", "")


def _scan_now(cfg: Config) -> ScanResult:
    """Run a scan synchronously, whether or not we're inside an event loop."""
    def runner() -> ScanResult:
        return asyncio.run(Orchestrator(cfg).run())
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return runner()
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(runner).result()


def _prompt(rel: str, content: str, findings: List[Finding]) -> str:
    issues = []
    for f in findings:
        issues.append(
            f"- [{f.effective_severity.value}] {f.rule_id} (line {f.line}): {f.title}\n"
            f"  Why: {f.why[:300]}\n  Fix guidance: {f.fix[:300]}"
            + (f"\n  Secure example:\n{f.secure_example}" if f.secure_example else "")
        )
    lang = "tsx" if rel.endswith((".tsx", ".jsx")) else "typescript" if rel.endswith(".ts") else "javascript"
    return (
        f"File: {rel}\n\nSecurity findings to fix:\n" + "\n".join(issues) +
        f"\n\nCurrent file:\n```{lang}\n{content}\n```\n\nReturn the complete corrected file."
    )


def _retry_prompt(rel: str, previous: str, still: List[str], introduced: List[str]) -> str:
    """Feedback prompt: tell the model exactly how its last patch fell short."""
    problems = []
    if still:
        problems.append(f"these issues are STILL present: {', '.join(sorted(set(still)))}")
    if introduced:
        problems.append(f"your change INTRODUCED new issues: {', '.join(sorted(set(introduced)))}")
    lang = "tsx" if rel.endswith((".tsx", ".jsx")) else "typescript" if rel.endswith(".ts") else "javascript"
    return (
        f"Your previous patch of {rel} was re-scanned and did not pass: " + "; ".join(problems) + ".\n"
        "Produce a new COMPLETE corrected file that resolves ALL the issues and introduces none. "
        "Keep behavior and style intact.\n\nYour previous attempt:\n"
        f"```{lang}\n{previous}\n```\n\nReturn the corrected file."
    )


def _strip_fences(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip("\n") + "\n"


def _diff(before: str, after: str, name: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{name}", tofile=f"b/{name}",
    ))

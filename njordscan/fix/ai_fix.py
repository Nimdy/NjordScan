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

    if provider is None:
        from ..explain.providers import ProviderError, get_provider
        try:
            provider = get_provider(config.ai_provider or "ollama")
        except ProviderError as exc:
            report.error = str(exc)
            return report
    report.provider = getattr(provider, "name", "ai")
    ok, reason = provider.check()
    if not ok:
        report.error = reason
        return report

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

            corrected = _strip_fences(provider.complete(_SYSTEM, _prompt(rel, original, by_file[rel])))
            if not corrected or corrected.strip() == original.strip():
                report.unverified.append(rel)
                continue

            tfile = tmproot / rel
            tfile.write_text(corrected, encoding="utf-8")
            try:
                rescan = _scan_now(scan_cfg)
            except Exception:  # noqa: BLE001
                tfile.write_text(original, encoding="utf-8")
                report.unverified.append(rel)
                continue

            # Only ``rel`` changed, so only its findings can move. Verify every targeted
            # rule's count dropped and no rule's count went up (no new issue introduced).
            after_rules = Counter(f.rule_id for f in rescan.findings if f.file == rel)
            target_resolved = all(after_rules[r] < before_rules[r] for r in before_rules)
            no_regression = all(after_rules[r] <= before_rules.get(r, 0) for r in after_rules)

            if target_resolved and no_regression:
                report.applied.append(AiFix(rel, sorted(before_rules), _diff(original, corrected, rel)))
                if not dry_run:
                    src.write_text(corrected, encoding="utf-8")
                # keep the verified fix in the temp tree for subsequent files
            else:
                tfile.write_text(original, encoding="utf-8")
                report.unverified.append(rel)

    return report


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

"""Scan orchestration.

Loads the project, runs all applicable detectors concurrently, enriches findings
with educational content, de-duplicates, filters by severity, and returns a
:class:`ScanResult`. A crash in one detector is isolated and reported rather than
failing the whole scan — a scanner that dies on one weird file is useless.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List

from ..detectors import load_detectors
from ..detectors.base import Detector
from ..knowledge import enrich
from .config import Config
from .finding import Finding
from .project import Project
from .severity import Severity


@dataclass
class ScanResult:
    project: Project
    findings: List[Finding]
    errors: List[str] = field(default_factory=list)
    duration_s: float = 0.0
    files_scanned: int = 0

    @property
    def counts(self) -> Dict[Severity, int]:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.effective_severity] += 1
        return out

    @property
    def total(self) -> int:
        return len(self.findings)

    def exceeds(self, threshold: Severity) -> bool:
        return any(f.effective_severity.meets(threshold) for f in self.findings)


class Orchestrator:
    def __init__(self, config: Config) -> None:
        self.config = config

    async def run(self) -> ScanResult:
        started = time.perf_counter()
        project = Project.load(self.config)
        detectors = self._select(load_detectors())

        errors: List[str] = []
        results = await asyncio.gather(
            *(self._run_one(d, project) for d in detectors),
            return_exceptions=True,
        )

        findings: List[Finding] = []
        for detector, result in zip(detectors, results):
            if isinstance(result, BaseException):
                errors.append(f"detector '{detector.id}' failed: {result!r}")
            else:
                findings.extend(result)

        findings = [enrich(f) for f in findings]
        findings = self._apply_rule_controls(findings)
        findings = self._dedupe(findings)
        findings = [
            f for f in findings if f.effective_severity.meets(self.config.min_severity)
        ]
        if self.config.reachability:
            self._annotate_reachability(findings, project)
        # reachable findings sort first within a severity tier
        findings.sort(key=lambda f: (-f.effective_severity.rank, f.reachable is False, f.file, f.line))

        return ScanResult(
            project=project,
            findings=findings,
            errors=errors,
            duration_s=time.perf_counter() - started,
            files_scanned=len(project.source_files),
        )

    # 'quick' mode skips the heavier detectors (tree-sitter taint parsing, advisory
    # matching) for fast feedback; 'standard'/'deep' run everything applicable.
    _QUICK_SKIP = {"taint", "dependencies"}

    def _select(self, detectors: List[Detector]) -> List[Detector]:
        only = self.config.only_detectors
        skip = set(self.config.skip_detectors)
        if self.config.mode == "quick" and only is None:
            skip |= self._QUICK_SKIP
        chosen = []
        for d in detectors:
            if only is not None and d.id not in only:
                continue
            if d.id in skip:
                continue
            chosen.append(d)
        return chosen

    async def _run_one(self, detector: Detector, project: Project) -> List[Finding]:
        if not detector.applies(project):
            return []
        return await detector.scan(project)

    def _annotate_reachability(self, findings: List[Finding], project: Project) -> None:
        """Mark each finding reachable/unreachable from a framework entrypoint."""
        from .reachability import ReachabilityGraph

        try:
            graph = ReachabilityGraph(project)
        except Exception:  # noqa: BLE001 — reachability is best-effort
            return
        if graph.entrypoint_count == 0:
            return  # no entrypoints detected → inconclusive, leave reachable = None

        source_rels = {project.rel(p) for p in project.source_files}
        for f in findings:
            if f.reachable is not None:
                continue  # a detector already determined reachability (e.g. dependency VEX)
            if f.file in source_rels:
                r = graph.lookup(f.file)
                f.reachable = r.reachable
                if r.reachable:
                    f.metadata["reachability"] = {
                        "kind": r.kind, "entrypoint": r.entrypoint, "path": r.path,
                    }
            else:
                # package.json / .env / lockfile / live-URL findings are inherently "live"
                f.reachable = True
                f.metadata.setdefault("reachability", {"kind": "project"})

        if self.config.reachable_only:
            findings[:] = [f for f in findings if f.reachable is not False]

    def _apply_rule_controls(self, findings: List[Finding]) -> List[Finding]:
        """Drop disabled rules and apply per-rule severity overrides from config."""
        disabled = self.config.disabled_rules
        overrides = self.config.severity_overrides
        out: List[Finding] = []
        for f in findings:
            if f.rule_id in disabled:
                continue
            override = overrides.get(f.rule_id)
            if override is not None:
                f.severity = override if isinstance(override, Severity) else Severity.from_str(str(override))
            out.append(f)
        return out

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        seen: set[str] = set()
        out: List[Finding] = []
        for f in findings:
            fp = f.fingerprint
            if fp in seen:
                continue
            seen.add(fp)
            out.append(f)
        return out

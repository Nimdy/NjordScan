"""Detector contract.

A detector inspects a :class:`~njordscan.core.project.Project` and yields raw
:class:`~njordscan.core.finding.Finding` objects. Detectors should populate
``rule_id`` and the location/snippet; the orchestrator enriches the educational
fields from the knowledge registry afterwards.

Detectors are async so I/O-bound or CPU-bound work can be offloaded with
``asyncio.to_thread`` without blocking the event loop.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..core.finding import Finding
from ..core.project import Project


class Detector(ABC):
    """Base class for all detectors."""

    #: stable, unique id used for --only/--skip and reporting (e.g. "secrets")
    id: str = ""
    #: human-friendly name shown in reports
    name: str = ""
    #: "static" runs on files; "dynamic" hits a live server (opt-in)
    kind: str = "static"

    def applies(self, project: Project) -> bool:
        """Whether this detector should run for the given project. Override as needed."""
        return True

    @abstractmethod
    async def scan(self, project: Project) -> List[Finding]:
        """Return findings for ``project``. Must not raise on malformed input."""
        raise NotImplementedError

    # -- small helpers shared by detectors ----------------------------------

    @staticmethod
    def _line_of(text: str, index: int) -> int:
        """1-based line number of character ``index`` in ``text``."""
        return text.count("\n", 0, index) + 1

    @staticmethod
    def _snippet(text: str, line: int, context: int = 0) -> str:
        lines = text.splitlines()
        if not (1 <= line <= len(lines)):
            return ""
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        return "\n".join(lines[start:end]).strip()

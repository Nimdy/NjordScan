"""The :class:`Finding` model — the heart of NjordScan.

A finding is more than "there is a bug on line 7". For a developer who is not a
security expert, a finding has to *teach*: what is this, why is it dangerous, and
how do I fix it. So every :class:`Finding` carries an educational payload
(``why`` / ``fix`` / ``secure_example``) alongside the location and metadata.

Detectors produce findings with just a ``rule_id`` and a location; the knowledge
registry (:mod:`njordscan.knowledge`) enriches them with the educational content,
title, severity, and standards mappings — so detector code stays focused on
*finding* things. A detector may still override severity/confidence/message per
occurrence.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .severity import Severity


@dataclass(frozen=True)
class TaintStep:
    """One hop in a taint flow, from a user-controlled source to a dangerous sink."""

    label: str          # human label, e.g. "req.body.name" or "renderHtml(input)"
    file: str
    line: int
    kind: str           # "source" | "propagation" | "sink"
    code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single security issue, complete with an explanation a beginner can act on.

    Required from a detector: ``rule_id`` and ``file`` (plus ideally ``line`` and
    ``code_snippet``). Everything else is enriched from the knowledge base.
    """

    # --- identity & location (detector-supplied) ---
    rule_id: str                       # stable id, e.g. "xss.dangerously-set-inner-html"
    file: str                          # path relative to the scanned project root
    line: int = 0
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    code_snippet: str = ""             # the offending line(s)
    detector: str = ""                 # which detector produced it
    message: str = ""                  # specific to this occurrence (optional)
    confidence: str = "medium"         # "high" | "medium" | "low"

    # --- enriched from the knowledge base (leave default; enrich() fills these) ---
    title: str = ""
    severity: Optional[Severity] = None
    why: str = ""
    fix: str = ""
    secure_example: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    attack: List[str] = field(default_factory=list)   # MITRE ATT&CK technique ids, e.g. ["T1059.007"]
    references: List[str] = field(default_factory=list)

    # --- optional extras ---
    taint_flow: List[TaintStep] = field(default_factory=list)
    ai_explanation: Optional[str] = None   # populated by an opt-in LLM provider
    reachable: Optional[bool] = None       # set by reachability analysis (None = not analyzed)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """A stable hash identifying this finding for dedup and baselines.

        Deliberately excludes the message so cosmetic wording changes don't
        create "new" findings across runs.
        """
        basis = f"{self.rule_id}|{self.file}|{self.line}|{self.code_snippet.strip()}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def effective_severity(self) -> Severity:
        """Severity, guaranteed non-None (defaults to MEDIUM if somehow unset)."""
        return self.severity if self.severity is not None else Severity.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.effective_severity.value
        data["fingerprint"] = self.fingerprint
        data["location"] = self.location
        data["taint_flow"] = [s.to_dict() for s in self.taint_flow]
        return data

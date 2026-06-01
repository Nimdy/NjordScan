"""Scan configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .severity import Severity

# Sensible default ignore globs. We DELIBERATELY do not ignore .env files —
# leaked secrets in committed env files are one of the most common real issues.
DEFAULT_IGNORES: List[str] = [
    "**/node_modules/**",
    "**/.git/**",
    "**/.next/**",
    "**/dist/**",
    "**/build/**",
    "**/coverage/**",
    "**/.turbo/**",
    "**/.vercel/**",
    "**/*.min.js",
    "**/*.bundle.js",
    "**/*.map",
]

# Source file extensions we statically analyse.
CODE_EXTENSIONS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})


@dataclass
class Config:
    """Everything a scan needs to know. Constructed by the CLI, passed to the orchestrator."""

    target: Path
    mode: str = "standard"                       # "quick" | "standard" | "deep"
    min_severity: Severity = Severity.INFO       # hide findings below this
    fail_on: Optional[Severity] = None           # exit nonzero if any finding >= this
    ignores: List[str] = field(default_factory=lambda: list(DEFAULT_IGNORES))
    extra_ignores: List[str] = field(default_factory=list)
    only_detectors: Optional[List[str]] = None   # run only these detector ids
    skip_detectors: List[str] = field(default_factory=list)
    disabled_rules: set = field(default_factory=set)        # rule_ids to suppress
    severity_overrides: dict = field(default_factory=dict)  # rule_id -> Severity
    max_file_bytes: int = 2_000_000              # skip files larger than this
    explain_with_ai: bool = False
    ai_provider: Optional[str] = None            # "ollama" | "claude" | "openai"
    ai_redact: bool = True                       # redact code before sending to an API
    no_external: bool = False                    # hard-block any network egress
    # Dynamic scanning (opt-in): a live URL to probe (DAST + live headers).
    url: Optional[str] = None
    allow_private: bool = False                  # allow scanning private/loopback hosts (off = SSRF-safe)
    dynamic_timeout: float = 10.0

    @property
    def all_ignores(self) -> List[str]:
        return [*self.ignores, *self.extra_ignores]

    def __post_init__(self) -> None:
        self.target = Path(self.target).resolve()

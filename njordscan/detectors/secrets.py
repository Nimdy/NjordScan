"""Secret detection.

Finds hard-coded credentials in source files AND in committed env files
(.env, .env.local, ...). V1 missed env-file secrets entirely; this is one of the
most common and most damaging real-world issues, so it is a first-class detector
here.

Design notes:
  - Patterns are split into high-confidence "provider" patterns (a match is almost
    certainly a real key) and a lower-confidence generic assignment pattern guarded
    by an entropy check (to avoid flagging `password = ""` or `apiKey = 'TODO'`).
  - We skip obvious placeholders ("changeme", "example", "xxxx", env-var lookups).
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Pattern

from ..core.finding import Finding
from ..core.project import Project
from .base import Detector

# Files we scan for secrets in addition to normal source files.
_ENV_GLOBS = (".env", ".env.*", "*.env")
_EXTRA_SECRET_FILES = (
    "*.pem", "*.key", "*.p12", "*.pfx",
    "config.json", "credentials.json", "secrets.json", "serviceAccount*.json",
)

_PLACEHOLDER_TOKENS = (
    "example", "changeme", "your-", "yours", "placeholder", "dummy", "test",
    "xxxx", "<", "}", "process.env", "import.meta.env", "redacted", "todo",
    "sample", "fake", "0000000000",
)


@dataclass(frozen=True)
class _SecretPattern:
    rule_id: str
    name: str
    regex: Pattern[str]
    confidence: str = "high"
    min_entropy: float = 0.0   # require this Shannon entropy on the captured value


def _p(rule_id: str, name: str, pattern: str, confidence: str = "high", min_entropy: float = 0.0) -> _SecretPattern:
    return _SecretPattern(rule_id, name, re.compile(pattern), confidence, min_entropy)


# High-confidence provider patterns.
# If a pattern defines a named group ``val`` it holds the sensitive value; otherwise
# the whole match is the value. Use ``(?:...)`` for non-value sub-groups.
_PROVIDER_PATTERNS: List[_SecretPattern] = [
    _p("secret.aws-access-key", "AWS Access Key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _p("secret.aws-access-key", "AWS Secret Access Key",
       r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?(?P<val>[A-Za-z0-9/+=]{40})['\"]?", min_entropy=3.5),
    _p("secret.private-key", "Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
    _p("secret.generic", "GitHub token", r"\bghp_[A-Za-z0-9]{36}\b"),
    _p("secret.generic", "GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    _p("secret.generic", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    _p("secret.generic", "Stripe secret key", r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    _p("secret.generic", "Stripe restricted key", r"\brk_live_[A-Za-z0-9]{16,}\b"),
    _p("secret.generic", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("secret.generic", "OpenAI API key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b", confidence="medium"),
    _p("secret.generic", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    _p("secret.generic", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b"),
    _p("secret.generic", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
    _p("secret.generic", "JWT (HS/RS signed token)", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", confidence="low"),
    _p("secret.generic", "Database URL with credentials",
       r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s'\"]+:(?P<val>[^@\s'\"]{3,})@", confidence="high"),
]

# Generic "NAME = value" assignment for secret-ish names, entropy-guarded.
_GENERIC_ASSIGN = re.compile(
    r"""(?ix)
    \b(
        [A-Za-z0-9_]*
        (?:secret|passwd|password|token|api[_-]?key|apikey|access[_-]?key|
           private[_-]?key|client[_-]?secret|auth[_-]?token|encryption[_-]?key)
        [A-Za-z0-9_]*
    )
    \s*[=:]\s*
    ['"]([^'"\n]{8,})['"]
    """,
)

# Next.js / Vite public-prefix exposure of a value that looks secret.
_PUBLIC_PREFIX = re.compile(
    r"""(?ix)
    \b(NEXT_PUBLIC_|VITE_)
    ([A-Za-z0-9_]*(?:secret|token|api[_-]?key|password|private[_-]?key|access[_-]?key)[A-Za-z0-9_]*)
    \s*[=:]\s*
    ['"]?([^'"\n#]{6,})
    """,
)


class SecretsDetector(Detector):
    id = "secrets"
    name = "Hard-coded secrets"
    kind = "static"

    async def scan(self, project: Project) -> List[Finding]:
        files = self._files_to_scan(project)
        results = await asyncio.gather(
            *(asyncio.to_thread(self._scan_file, project, path) for path in files)
        )
        findings: List[Finding] = []
        for chunk in results:
            findings.extend(chunk)
        return findings

    def _files_to_scan(self, project: Project) -> List[Path]:
        files = list(project.source_files)
        seen = set(files)
        for pattern in (*_ENV_GLOBS, *_EXTRA_SECRET_FILES):
            for path in project.root.rglob(pattern):
                if path.is_file() and path not in seen and not project.is_ignored(path):
                    try:
                        if path.stat().st_size <= project.config.max_file_bytes:
                            files.append(path)
                            seen.add(path)
                    except OSError:
                        continue
        return files

    def _scan_file(self, project: Project, path: Path) -> List[Finding]:
        text = project.read_text(path)
        if not text:
            return []
        rel = project.rel(path)
        findings: List[Finding] = []

        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(line) > 1000:  # skip minified / data lines
                continue
            findings.extend(self._scan_line(rel, line_no, line))
        return findings

    def _scan_line(self, rel: str, line_no: int, line: str) -> List[Finding]:
        out: List[Finding] = []
        matched_spans: List[tuple[int, int]] = []

        for pat in _PROVIDER_PATTERNS:
            for m in pat.regex.finditer(line):
                value = m.groupdict().get("val") or m.group(0)
                if self._is_placeholder(value):
                    continue
                if pat.min_entropy and _entropy(value) < pat.min_entropy:
                    continue
                out.append(Finding(
                    rule_id=pat.rule_id,
                    file=rel,
                    line=line_no,
                    column=m.start() + 1,
                    code_snippet=_mask(line.strip()),
                    detector=self.id,
                    confidence=pat.confidence,
                    message=f"Looks like a {pat.name}.",
                ))
                matched_spans.append(m.span())

        for m in _PUBLIC_PREFIX.finditer(line):
            value = m.group(3).strip()
            if self._is_placeholder(value) or _entropy(value) < 3.0:
                continue
            out.append(Finding(
                rule_id="secret.public-env-exposure",
                file=rel,
                line=line_no,
                column=m.start() + 1,
                code_snippet=_mask(line.strip()),
                detector=self.id,
                confidence="medium",
                message=f"`{m.group(1)}{m.group(2)}` is exposed to the browser bundle.",
            ))

        for m in _GENERIC_ASSIGN.finditer(line):
            if any(s <= m.start() < e for s, e in matched_spans):
                continue  # already reported by a provider pattern
            value = m.group(2)
            if self._is_placeholder(value) or _entropy(value) < 3.2:
                continue
            out.append(Finding(
                rule_id="secret.generic",
                file=rel,
                line=line_no,
                column=m.start() + 1,
                code_snippet=_mask(line.strip()),
                detector=self.id,
                confidence="medium",
                message=f"`{m.group(1)}` is assigned a high-entropy literal that looks like a secret.",
            ))
        return out

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        v = value.strip().lower()
        if len(v) < 6:
            return True
        return any(token in v for token in _PLACEHOLDER_TOKENS)


def _entropy(value: str) -> float:
    """Shannon entropy (bits/char) — high for random keys, low for words/placeholders."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mask(line: str, keep: int = 4) -> str:
    """Mask long high-entropy runs so we don't print the full secret into reports."""
    def repl(m: "re.Match[str]") -> str:
        tok = m.group(0)
        if len(tok) <= keep + 2 or _entropy(tok) < 3.0:
            return tok
        return tok[:keep] + "…" + "*" * 4
    return re.sub(r"[A-Za-z0-9/+_\-]{12,}", repl, line)

"""Redaction for code sent to remote AI providers.

When a user opts into an *external* LLM (Claude/OpenAI), we send a small code
snippet for context. By default we redact anything that looks like a secret first,
so a scan never leaks credentials to a third party. Local providers (Ollama) run
on the user's machine, so redaction there is optional.
"""

from __future__ import annotations

import math
import re

# Reuse the same idea as the secrets detector: mask long high-entropy runs and
# common secret shapes before the snippet ever leaves the machine.
_SECRET_SHAPES = re.compile(
    r"(AKIA[0-9A-Z]{16}"
    r"|sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"
    r"|sk-ant-[A-Za-z0-9_\-]{20,}"
    r"|sk_live_[A-Za-z0-9]{16,}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|AIza[0-9A-Za-z_\-]{35}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9/+_\-]{20,}")
_URL_CREDS = re.compile(r"(://[^:\s/]+:)[^@\s]+(@)")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(snippet: str) -> str:
    """Return ``snippet`` with likely secrets replaced by a ``‹redacted›`` marker."""
    if not snippet:
        return snippet
    text = _SECRET_SHAPES.sub("‹redacted-secret›", snippet)
    text = _URL_CREDS.sub(r"\1‹redacted›\2", text)

    def _mask_token(m: "re.Match[str]") -> str:
        tok = m.group(0)
        if _entropy(tok) >= 3.6:  # looks random -> probably a key/token
            return "‹redacted›"
        return tok

    return _LONG_TOKEN.sub(_mask_token, text)

"""Redaction for code sent to remote AI providers.

When a user opts into an *external* LLM (Claude/OpenAI), we send a small code
snippet for context. By default we redact anything that looks like a secret first,
so a scan never leaks credentials to a third party. Local providers (Ollama) run
on the user's machine, so redaction there is optional.

Redaction is a *safety boundary*, so the bias is deliberately toward over-masking:
it is always better to send the model ``password = "‹redacted›"`` than to leak a
real credential. We reuse the secrets detector's trusted provider matchers as the
source of truth, and add name-based assignment redaction (a literal assigned to a
secret-ish identifier is masked regardless of entropy) plus a connection-URL rule
that correctly handles ``@`` inside a password.
"""

from __future__ import annotations

import math
import re

# Reuse the secrets detector's trusted provider matchers as the source of truth,
# so a key shape the scanner flags is also a key shape we redact. Fall back to a
# local baseline if the import ever fails — redaction must never hard-error.
try:  # pragma: no cover - exercised indirectly
    from ..detectors.secrets import _PROVIDER_PATTERNS as _SECRET_PATTERNS
except Exception:  # pragma: no cover - defensive
    _SECRET_PATTERNS = []

# Always-on baseline of common provider key shapes (independent of the import).
_SECRET_SHAPES = re.compile(
    r"(AKIA[0-9A-Z]{16}"
    r"|sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"
    r"|sk-ant-[A-Za-z0-9_\-]{20,}"
    r"|sk_live_[A-Za-z0-9]{16,}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|AIza[0-9A-Za-z_\-]{35}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
)

# A literal assigned to an identifier whose name contains a strong secret keyword.
# These keywords almost never appear in non-secret identifiers, so we mask the
# value regardless of entropy (a weak password is still a credential).
_STRONG_NAME = (
    r"(?:secret|passwd|password|passphrase|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|"
    r"credential|mnemonic|seed[_-]?phrase)"
)
# The quote can be ', " OR a backtick — `const pw = `secret`` is idiomatic modern JS
# and must redact exactly like the quoted forms.
_SECRET_ASSIGN = re.compile(
    rf"(?ix)\b([A-Za-z0-9_]*{_STRONG_NAME}[A-Za-z0-9_]*)(\s*[=:]\s*)(['\"`])([^'\"`\n]{{3,}})(['\"`])"
)

# Short, generic credential identifiers (pw, pwd, pass, key, secret) that are too
# noisy to allow as substrings — require them to be a *whole* identifier so we
# don't mask "author" or "keyboard". Still over-masks within that constraint.
_SECRET_ASSIGN_SHORT = re.compile(
    r"(?ix)(?<![A-Za-z0-9_])(pw|pwd|pass|passwd|key|secret)(\s*[=:]\s*)(['\"`])([^'\"`\n]{3,})(['\"`])"
)

# Credentials embedded in a connection URL. Greedy up to the LAST '@' so a
# password that itself contains '@' (postgres://user:p@ss@host) is fully masked.
_URL_CREDS = re.compile(r"(://[^:\s/'\"]+:)[^\s'\"]+(@)")

# Long high-entropy runs that look like a random key/token.
_LONG_TOKEN = re.compile(r"[A-Za-z0-9/+_\-]{20,}")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mask_token(m: "re.Match[str]") -> str:
    tok = m.group(0)
    if _entropy(tok) >= 3.6:  # looks random -> probably a key/token
        return "‹redacted›"
    return tok


def _redact_provider(m: "re.Match[str]") -> str:
    """Replace the sensitive value of a provider-pattern match, keeping context."""
    val = m.groupdict().get("val")
    if val:
        return m.group(0).replace(val, "‹redacted-secret›")
    return "‹redacted-secret›"


def redact(snippet: str) -> str:
    """Return ``snippet`` with likely secrets replaced by a ``‹redacted›`` marker."""
    if not snippet:
        return snippet

    text = snippet
    # 1. Known provider key shapes (reuse the secrets detector's trusted matchers).
    for pat in _SECRET_PATTERNS:
        try:
            text = pat.regex.sub(_redact_provider, text)
        except Exception:  # pragma: no cover - a single bad pattern can't break redaction
            continue
    text = _SECRET_SHAPES.sub("‹redacted-secret›", text)

    # 2. Credentials embedded in a connection URL (handles '@' inside the password).
    text = _URL_CREDS.sub(r"\1‹redacted›\2", text)

    # 3. A literal assigned to a secret-ish identifier (name-based; over-masks).
    text = _SECRET_ASSIGN.sub(r"\1\2\3‹redacted›\5", text)
    text = _SECRET_ASSIGN_SHORT.sub(r"\1\2\3‹redacted›\5", text)

    # 4. Long high-entropy runs that look random.
    text = _LONG_TOKEN.sub(_mask_token, text)
    return text

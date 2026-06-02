"""Opt-in AI explanation layer (Tier 2/3).

Tier 1 — the offline why/fix/secure-example every finding already carries — needs
nothing here. This package only adds optional, consented AI enrichment on top.
"""

from __future__ import annotations

from .engine import explain_findings
from .providers import ProviderError, get_provider

__all__ = ["explain_findings", "get_provider", "ProviderError"]

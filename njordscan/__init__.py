"""NjordScan — a security scanner for Next.js, React, and Vite apps.

NjordScan is built for developers who are not security experts. Every finding it
reports comes with a plain-English explanation of *why* it matters and *how* to
fix it, so you can ship safely without a security background.

Public API is intentionally small; most users interact via the ``njordscan`` CLI.
"""

from __future__ import annotations

__version__ = "2.0.0b1"

from .core.finding import Finding, TaintStep
from .core.severity import Severity

__all__ = ["Finding", "TaintStep", "Severity", "__version__"]

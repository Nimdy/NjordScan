"""Severity levels and their presentation."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Ordered severity levels.

    Inherits from ``str`` so values serialize cleanly to JSON/SARIF and compare
    equal to their string form (e.g. ``Severity.HIGH == "high"``).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher number = more severe. Useful for sorting and threshold gates."""
        return _RANK[self]

    @property
    def emoji(self) -> str:
        return _EMOJI[self]

    @property
    def color(self) -> str:
        """A ``rich`` color/style name for terminal rendering."""
        return _COLOR[self]

    @property
    def sarif_level(self) -> str:
        """Map to the SARIF ``level`` vocabulary (error/warning/note)."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def security_severity(self) -> float:
        """Numeric score (0-10) used by GitHub code scanning for SARIF results."""
        return _SECURITY_SEVERITY[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls(value.strip().lower())

    def meets(self, threshold: "Severity") -> bool:
        """True if this severity is at least as severe as ``threshold``."""
        return self.rank >= threshold.rank


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim white",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

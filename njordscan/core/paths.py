"""User data locations (cache, refreshed advisories)."""

from __future__ import annotations

import os
from pathlib import Path


def user_data_dir() -> Path:
    """``~/.njordscan`` (respects $NJORDSCAN_HOME and $XDG_DATA_HOME)."""
    override = os.getenv("NJORDSCAN_HOME")
    if override:
        return Path(override)
    xdg = os.getenv("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "njordscan"
    return Path.home() / ".njordscan"


def user_advisories_path() -> Path:
    """Where ``njordscan update`` writes refreshed dependency advisories."""
    return user_data_dir() / "advisories.json"


def user_rules_dir() -> Path:
    """Where ``njordscan update`` writes self-updating knowledge rules (YAML)."""
    return user_data_dir() / "rules"


def user_patterns_dir() -> Path:
    """Where ``njordscan update`` writes self-updating detection patterns (YAML)."""
    return user_data_dir() / "patterns"

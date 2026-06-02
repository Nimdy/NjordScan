"""Reporters: render a :class:`~njordscan.core.orchestrator.ScanResult`."""

from __future__ import annotations

from typing import Callable, Dict

from ..core.orchestrator import ScanResult
from .attack_navigator import render_attack_navigator
from .html import render_html
from .json_report import render_json
from .sarif import render_sarif
from .terminal import render_terminal

# format name -> renderer returning a string (terminal renders to console directly)
_FILE_RENDERERS: Dict[str, Callable[[ScanResult], str]] = {
    "json": render_json,
    "sarif": render_sarif,
    "html": render_html,
    "attack-navigator": render_attack_navigator,
}


def render_to_string(result: ScanResult, fmt: str) -> str:
    if fmt not in _FILE_RENDERERS:
        raise ValueError(f"Unknown file format: {fmt}")
    return _FILE_RENDERERS[fmt](result)


def available_formats() -> list[str]:
    return ["terminal", *sorted(_FILE_RENDERERS)]


__all__ = [
    "render_terminal", "render_json", "render_sarif", "render_html",
    "render_to_string", "available_formats",
]

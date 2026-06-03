"""Detector registry.

``load_detectors()`` returns one instance of every available detector. Detector
modules are imported defensively: if one cannot import (e.g. an optional parser
dependency is missing), it is skipped with a logged warning rather than taking
the whole scan down. A security tool must degrade gracefully, never crash.
"""

from __future__ import annotations

import importlib
import logging
from typing import List

from .base import Detector

logger = logging.getLogger(__name__)

# (module, class) pairs. Order is cosmetic; results are sorted later.
_REGISTRY = [
    ("njordscan.detectors.secrets", "SecretsDetector"),
    ("njordscan.detectors.supply_chain", "SupplyChainDetector"),
    ("njordscan.detectors.dependencies", "DependenciesDetector"),
    ("njordscan.detectors.static_analysis", "StaticAnalysisDetector"),
    ("njordscan.detectors.taint", "TaintDetector"),
    ("njordscan.detectors.ai_agency", "AIAgencyDetector"),
    ("njordscan.detectors.configs", "ConfigsDetector"),
    ("njordscan.detectors.pattern_engine", "PatternEngine"),
    ("njordscan.detectors.git_hygiene", "GitHygieneDetector"),
    ("njordscan.detectors.runtime", "DynamicScanDetector"),
]


def load_detectors() -> List[Detector]:
    detectors: List[Detector] = []
    for module_name, class_name in _REGISTRY:
        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)
        except ModuleNotFoundError as exc:
            # Detector not built yet, or an optional dependency is absent. Expected.
            logger.debug("Detector %s not available: %s", class_name, exc)
            continue
        except Exception as exc:  # noqa: BLE001 — intentional: isolate optional detectors
            logger.warning("Detector %s failed to import: %s", class_name, exc)
            continue
        try:
            detectors.append(cls())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Detector %s failed to initialize: %s", class_name, exc)
    return detectors


__all__ = ["Detector", "load_detectors"]

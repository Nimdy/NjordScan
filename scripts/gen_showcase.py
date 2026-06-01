#!/usr/bin/env python3
"""Regenerate the committed showcase outputs for examples/vulnerable-shop.

These files are what a visitor sees in the README before installing anything, so
they must always reflect current behavior. Run after changing detectors, rules, or
the attack-path engine:

    python scripts/gen_showcase.py

Writes into examples/vulnerable-shop/sample-output/:
  scan.txt              — the full rich terminal report (ANSI stripped)
  report.html           — the shareable HTML report
  sbom.cdx.json         — CycloneDX SBOM with VEX
  attack-navigator.json — MITRE ATT&CK Navigator layer
  attack-paths.json     — just the synthesized attack paths (the headline)

Runs against an isolated NJORDSCAN_HOME so the developer's own cache/advisories
don't leak into the committed sample.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "examples" / "vulnerable-shop"
OUT = APP / "sample-output"


async def _main() -> None:
    # Isolate user data so the sample is deterministic (shipped seed only).
    os.environ["NJORDSCAN_HOME"] = tempfile.mkdtemp(prefix="njord-showcase-")
    shutil.rmtree(APP / ".njordscan", ignore_errors=True)

    from rich.console import Console

    from njordscan.core.config import Config
    from njordscan.core.orchestrator import Orchestrator
    from njordscan.report import render_terminal
    from njordscan.report.html import render_html
    from njordscan.report.json_report import build_report
    from njordscan.report.sarif import build_sarif  # noqa: F401  (import sanity)
    from njordscan.report.attack_navigator import render_attack_navigator
    from njordscan import sbom as sbom_mod

    result = await Orchestrator(Config(target=APP)).run()
    OUT.mkdir(parents=True, exist_ok=True)

    # terminal (ANSI stripped so it renders as plain text in the README)
    rec = Console(record=True, width=100, force_terminal=False)
    render_terminal(result, rec, show_fix=True)
    (OUT / "scan.txt").write_text(rec.export_text(), encoding="utf-8")

    (OUT / "report.html").write_text(render_html(result), encoding="utf-8")

    paths = [p.to_dict() for p in result.attack_paths]
    (OUT / "attack-paths.json").write_text(json.dumps(paths, indent=2), encoding="utf-8")

    full = build_report(result)
    (OUT / "scan.json").write_text(json.dumps(full, indent=2), encoding="utf-8")

    try:
        (OUT / "sbom.cdx.json").write_text(
            json.dumps(sbom_mod.to_cyclonedx(result.project), indent=2), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        print(f"  (sbom skipped: {exc})")
    (OUT / "attack-navigator.json").write_text(render_attack_navigator(result), encoding="utf-8")

    shutil.rmtree(APP / ".njordscan", ignore_errors=True)
    print(f"✓ Showcase regenerated in {OUT}")
    print(f"  {result.total} findings · {len(result.attack_paths)} attack paths "
          f"(top score {max((p.score for p in result.attack_paths), default=0)})")


if __name__ == "__main__":
    asyncio.run(_main())

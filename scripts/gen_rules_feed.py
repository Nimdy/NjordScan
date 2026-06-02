#!/usr/bin/env python3
"""Build the self-updating detection feed that ``njordscan update`` consumes.

This bundles the shipped YAML knowledge rules and detection patterns into a single
JSON manifest. Host the output somewhere over HTTPS (GitHub raw, S3, a CDN) and
point clients at it via ``$NJORDSCAN_RULES_FEED``; running ``njordscan update``
then pulls fresh rules + patterns without a reinstall.

    python scripts/gen_rules_feed.py                 # -> feed/rules-feed.json
    python scripts/gen_rules_feed.py --out path.json --version 2026.06.01

The manifest schema (mirrors update.fetch_rules_feed)::

    {"version": "...", "generated": "...", "tool_min_version": "...",
     "rules":    {"<name>.yaml": "<yaml text>"},
     "patterns": {"<name>.yaml": "<yaml text>"}}

Only the *data-driven* rules/patterns travel in the feed — the built-in core rules
in ``knowledge/rules.py`` ship with the package and always win, so the feed can
never downgrade or override a hand-authored core rule.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from njordscan import __version__

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "njordscan" / "data"
RULES_DIR = DATA / "rules"
PATTERNS_DIR = DATA / "patterns"


def _collect(directory: Path) -> dict[str, str]:
    """{filename: yaml_text} for every ``*.yaml`` in ``directory``."""
    out: dict[str, str] = {}
    if not directory.exists():
        return out
    for path in sorted(directory.glob("*.yaml")):
        out[path.name] = path.read_text(encoding="utf-8")
    return out


def build_manifest(version: str | None) -> dict:
    rules = _collect(RULES_DIR)
    patterns = _collect(PATTERNS_DIR)
    return {
        "version": version or datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_min_version": __version__,
        "rules": rules,
        "patterns": patterns,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "feed" / "rules-feed.json",
                    help="Output path (default: feed/rules-feed.json)")
    ap.add_argument("--version", default=None,
                    help="Feed version label (default: today's UTC date)")
    args = ap.parse_args()

    manifest = build_manifest(args.version)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    n_rules = len(manifest["rules"])
    n_patterns = len(manifest["patterns"])
    size_kb = args.out.stat().st_size / 1024
    print(f"✓ Wrote {args.out} — {n_rules} rule file(s) + {n_patterns} pattern file(s), "
          f"{size_kb:.1f} KB (version {manifest['version']})")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Pretty-print the keystone_paths array from a NjordScan --format json scan.

Reads the JSON report on stdin and renders, for each keystone path, which step
THIS change armed and which steps pre-existed (and who planted them, per git
blame). Used by build-history.sh to show the machine-readable side of the same
verdict the terminal 🔑 Keystone block displays.
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        print("  (could not parse JSON report)")
        return

    ks = data.get("keystone_paths", [])
    if not ks:
        print("  (no keystone paths reported)")
        return

    for k in ks:
        print(f"  - {k['title']}  [{k['kind']}, {k['band']}]")
        asm = ", ".join(k.get("assemblers") or []) or "earlier commits"
        print(f"    pre-existing links planted by: {asm}")
        for s in k["steps"]:
            if s["provenance"] == "newly-introduced":
                tag = "ARMED BY THIS CHANGE"
            else:
                who = s.get("born_author") or "?"
                when = s.get("born_date") or "?"
                tag = f"pre-existing — planted by {who} on {when}"
            print(f"      {s['order']}. [{s['tactic']}] {s['title']}  ({tag})")


if __name__ == "__main__":
    main()

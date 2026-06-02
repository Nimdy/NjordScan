#!/usr/bin/env python3
"""Arm / disarm the demo secrets in the example + simulation-lab fixtures.

The lab and examples deliberately contain "leaked" secrets so NjordScan has something
to find. The catch: a real-format provider key (an `AKIA…` AWS id, an `sk_live_…`
Stripe key) is, by design, blocked by GitHub push protection — which can't tell a
fake demo secret from a real leak. So the committed (DISARMED) state uses neutralized
values that NjordScan still flags (via its generic-secret heuristic) but no secret
scanner treats as a real provider key, and the repo pushes clean with no bypass.

When you want the full, provider-specific demo locally (so the report says "AWS access
key" / "Stripe key" rather than "generic secret"), run:

    python scripts/lab-secrets.py arm      # inject real-FORMAT fake keys (DO NOT COMMIT)
    python scripts/lab-secrets.py disarm   # restore the pushable placeholders
    python scripts/lab-secrets.py status   # show the current state

The real-format keys are GENERATED AT RUNTIME (built from fragments + random data), so
this script's own source never contains a committable provider literal. Armed files are
*not* gitignored on purpose: if you accidentally `git add` them, GitHub push protection
will stop you — that's the safety net working as intended.
"""

from __future__ import annotations

import re
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Each slot: a file, the DISARMED placeholder, and a regex that matches the ARMED
# (real-format) value so we can swap either way. `kind` picks the generator.
SLOTS = [
    {
        "file": "examples/vulnerable-shop/.env.local",
        "placeholder": "disarmed-run-make-arm-for-a-real-format-key",
        "armed_re": re.compile(r"AKIA[0-9A-Z]{16}"),
        "kind": "aws",
    },
    {
        "file": "simulation-lab/targets/01-vulnerable-nextjs/server.js",
        "placeholder": "lab_demo_key_a3f9c2b18d7e6f5a4b3c2d1e0f9a8b7c",
        "armed_re": re.compile(r"sk_live_[A-Za-z0-9]{16,}"),
        "kind": "stripe",
    },
]


def _gen(kind: str) -> str:
    """A real-FORMAT but entirely fake key, assembled so this source holds no literal."""
    alnum = string.ascii_letters + string.digits
    upper = string.ascii_uppercase + string.digits
    if kind == "aws":
        return "AK" + "IA" + "".join(secrets.choice(upper) for _ in range(16))
    if kind == "stripe":
        return "sk" + "_" + "live" + "_" + "".join(secrets.choice(alnum) for _ in range(30))
    raise ValueError(kind)


def _state(slot) -> str:
    text = (ROOT / slot["file"]).read_text(encoding="utf-8")
    if slot["placeholder"] in text:
        return "disarmed"
    if slot["armed_re"].search(text):
        return "armed"
    return "unknown"


def arm() -> None:
    for slot in SLOTS:
        p = ROOT / slot["file"]
        text = p.read_text(encoding="utf-8")
        if slot["placeholder"] in text:
            text = text.replace(slot["placeholder"], _gen(slot["kind"]))
            p.write_text(text, encoding="utf-8")
            print(f"  armed   {slot['file']}")
        else:
            print(f"  (already armed/unknown) {slot['file']}")
    print("\n⚠  Armed files now contain real-FORMAT fake keys. Do NOT commit them — run "
          "'disarm' first (GitHub push protection will block you otherwise).")


def disarm() -> None:
    for slot in SLOTS:
        p = ROOT / slot["file"]
        text = p.read_text(encoding="utf-8")
        new = slot["armed_re"].sub(slot["placeholder"], text)
        if new != text:
            p.write_text(new, encoding="utf-8")
            print(f"  disarmed {slot['file']}")
        else:
            print(f"  (already disarmed) {slot['file']}")


def status() -> None:
    for slot in SLOTS:
        print(f"  {_state(slot):9}  {slot['file']}")


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "arm":
        arm()
    elif cmd == "disarm":
        disarm()
    elif cmd == "status":
        status()
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

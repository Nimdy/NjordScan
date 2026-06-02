#!/usr/bin/env python3
"""Export the blue team's detections as portable Sigma rules.

The mini-SIEM (detect.py) is great for the lab, but real SOCs run Splunk / Elastic /
Sentinel / etc. Sigma (https://sigmahq.io) is the vendor-neutral detection format they
all speak. This emits one Sigma rule per blue-team detection — same indicators, same
MITRE ATT&CK tag, same severity — so the detections you tuned here are reusable in a
real SIEM via `sigma convert`.

    python3 gen-sigma.py            # writes sigma/*.yml next to this script

Dependency-free (standard library only — YAML is templated by hand, no PyYAML).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect  # noqa: E402

OUT = Path(__file__).resolve().parent / "sigma"
_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "njordscan-lab.sigma")
_LEVEL = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "informational"}

# Per-rule Sigma `detection:` body (the portable indicators). Keyed by rule name; the
# title / level / ATT&CK tag come from the live RULES so they never drift.
_DETECTION = {
    "reflected-xss": """  keywords:
    - '<script'
    - 'onerror='
    - 'onload='
    - 'javascript:'
    - '<svg'
    - '<iframe'
    - 'document.cookie'
    - 'alert('
  condition: keywords""",
    "sql-injection": """  keywords:
    - ' OR 1=1'
    - "' OR '"
    - 'UNION SELECT'
    - 'information_schema'
    - 'sleep('
    - 'benchmark('
    - '; DROP TABLE'
    - 'xp_cmdshell'
  condition: keywords""",
    "os-command-injection": """  keywords:
    - ';id'
    - ';cat'
    - ';whoami'
    - ';uname'
    - '$('
    - '|sh'
    - '|bash'
    - ';wget'
    - ';curl'
  condition: keywords""",
    "path-traversal": """  keywords:
    - '../'
    - '..\\\\'
    - '/etc/passwd'
    - '%2e%2e'
    - '..%2f'
  condition: keywords""",
    "open-redirect": """  sel:
    query|contains:
      - 'url=http'
      - 'next=http'
      - 'redirect=http'
      - 'return=http'
      - 'dest=http'
      - 'returnTo=http'
  condition: sel""",
    "scanner-tooling-ua": """  sel:
    ua|contains:
      - 'nmap'
      - 'nikto'
      - 'sqlmap'
      - 'njordscan'
      - 'gobuster'
      - 'nuclei'
      - 'ffuf'
      - 'wpscan'
      - 'masscan'
      - 'hydra'
  condition: sel""",
    "automated-client-ua": """  sel:
    ua|contains:
      - 'curl/'
      - 'wget/'
      - 'python-requests'
      - 'go-http-client'
      - 'httpie'
  condition: sel""",
    "verbose-error": """  sel:
    status: 500
  condition: sel""",
    "internal-tier-access": """  sel:
    svc: 'internal'
    path|startswith: '/admin'
  condition: sel""",
    "exfiltration-to-c2": """  sel:
    svc: 'c2'
  condition: sel""",
    "denial-of-wallet-burst": """  sel:
    path: '/api/chat'
  timeframe: 10s
  condition: sel | count() by ip > 5""",
}


def _rule_meta():
    for r in detect.RULES:
        yield r.name, r.severity, r.technique, r.description
    b = detect.BurstRule()
    yield b.name, b.severity, b.technique, b.description


def _sigma(name: str, severity: str, technique: str, desc: str) -> str:
    det = _DETECTION.get(name)
    if det is None:
        return ""
    tag = "attack." + technique.lower()
    rid = uuid.uuid5(_NS, name)
    desc1 = " ".join(desc.split())
    return f"""title: {name.replace('-', ' ').title()}
id: {rid}
status: experimental
description: {desc1}
references:
  - https://github.com/Nimdy/NjordScan
author: NjordScan Simulation Lab
date: 2026/06/02
logsource:
  product: njordscan-lab
  service: access-log
detection:
{det}
fields:
  - svc
  - ip
  - method
  - path
  - query
level: {_LEVEL.get(severity, 'medium')}
tags:
  - {tag}
"""


def main() -> int:
    OUT.mkdir(exist_ok=True)
    written = 0
    for name, severity, technique, desc in _rule_meta():
        doc = _sigma(name, severity, technique, desc)
        if not doc:
            print(f"  (skipped {name}: no Sigma detection mapping)", file=sys.stderr)
            continue
        (OUT / f"{name}.yml").write_text(doc, encoding="utf-8")
        written += 1
    print(f"✓ wrote {written} Sigma rules to {OUT}")
    print("  Convert for your SIEM, e.g.:  sigma convert -t splunk -p sysmon " + str(OUT) + "/*.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())

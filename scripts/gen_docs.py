#!/usr/bin/env python3
"""Generate docs/RULES.md from the knowledge base, so the catalog never drifts.

Run after adding or editing rules:
    python scripts/gen_docs.py
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from njordscan.knowledge import all_rules
from njordscan.core.severity import Severity

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "RULES.md"

# Friendly section titles for each rule-id namespace (prefix before the first dot).
CATEGORIES = {
    "secret": "Secrets & credentials",
    "xss": "Cross-site scripting (XSS)",
    "dom": "DOM-based XSS",
    "react": "React",
    "nextjs": "Next.js",
    "vite": "Vite",
    "injection": "Injection (eval / command / SSTI)",
    "sqli": "SQL injection",
    "nosqli": "NoSQL injection",
    "path-traversal": "Path traversal",
    "ssrf": "Server-side request forgery",
    "open-redirect": "Open redirect",
    "crypto": "Cryptography",
    "jwt": "JSON Web Tokens",
    "auth": "Authentication & credentials",
    "session": "Sessions",
    "cookie": "Cookies",
    "cors": "CORS",
    "csp": "Content-Security-Policy",
    "csrf": "CSRF",
    "headers": "Security headers (live)",
    "config": "Configuration",
    "supply-chain": "Supply chain",
    "deps": "Dependencies",
    "ai": "AI / LLM application security",
    "ai-endpoint": "AI endpoints (dynamic)",
    "dast": "Dynamic scan (DAST)",
    "hardening": "Hardening & info-leak",
    "info-leak": "Information leakage",
}

_ORDER = list(CATEGORIES.keys())


def _sev_badge(s: Severity) -> str:
    return f"{s.emoji} **{s.value}**"


def generate() -> str:
    rules = all_rules()
    by_cat: dict[str, list] = defaultdict(list)
    for r in rules:
        by_cat[r.id.split(".")[0]].append(r)

    cats = sorted(by_cat, key=lambda c: (_ORDER.index(c) if c in _ORDER else 999, c))

    lines = [
        "# NjordScan rules",
        "",
        f"NjordScan ships **{len(rules)} rules**. Every one is explained in plain English — why it "
        "matters and how to fix it — both here and inline when a scan finds it.",
        "",
        "> Auto-generated from the knowledge base by `scripts/gen_docs.py`. Don't edit by hand.",
        "",
        "Run `njordscan explain <rule-id>` for any of these in your terminal.",
        "",
        "## Contents",
        "",
    ]
    for c in cats:
        title = CATEGORIES.get(c, c.title())
        anchor = "".join(ch for ch in title.lower().replace(" ", "-") if ch.isalnum() or ch == "-")
        lines.append(f"- [{title}](#{anchor}) ({len(by_cat[c])})")
    lines.append("")

    for c in cats:
        title = CATEGORIES.get(c, c.title())
        lines.append(f"## {title}")
        lines.append("")
        for r in sorted(by_cat[c], key=lambda x: (-x.severity.rank, x.id)):
            lines.append(f"### `{r.id}` — {r.title}")
            lines.append("")
            meta = [f"Severity: {_sev_badge(r.severity)}"]
            if r.cwe:
                meta.append(f"[{r.cwe}](https://cwe.mitre.org/data/definitions/{r.cwe.split('-')[1]}.html)")
            if r.owasp:
                meta.append(r.owasp)
            lines.append("  ·  ".join(meta))
            lines.append("")
            lines.append(f"**Why this matters.** {r.why.strip()}")
            lines.append("")
            lines.append(f"**How to fix it.** {r.fix.strip()}")
            lines.append("")
            if r.secure_example.strip():
                lines.append("```js")
                lines.append(r.secure_example.strip())
                lines.append("```")
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(generate(), encoding="utf-8")
    print(f"Wrote {OUT} ({len(all_rules())} rules)")


if __name__ == "__main__":
    main()

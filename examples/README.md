# NjordScan examples

See NjordScan in action on a realistic app.

## `vulnerable-shop/` — a deliberately-insecure Next.js app

A small but realistic Next.js shop that contains the bugs real apps actually ship. Scan it:

```bash
pip install njordscan
njordscan scan examples/vulnerable-shop
```

You get **30 findings** — every one explained in plain English with a fix — spanning the whole
modern attack surface. The full captured report is in
[`vulnerable-shop/sample-output/scan.txt`](vulnerable-shop/sample-output/scan.txt).

### What it catches (and why it's special)

| Finding | Why it's notable |
|---------|------------------|
| 🔴 AWS key + DB creds in `.env.local` | secrets in committed env files (masked in output) |
| 🔴 SQL injection in `lib/db.ts` | reachable from the `/api/products` route |
| 🔴 Dangerous `postinstall` (`curl \| bash`) | supply-chain attack before your app even runs |
| 🟠 **Cross-file XSS** `req.body → paint() → innerHTML` | taint followed **across module boundaries** |
| 🟠 LLM output rendered as HTML, unauth AI endpoint | **AI-app security** (XSS + denial-of-wallet) |
| 🟠 `lodash` CVE-2021-23337 → **`exploitable`** | you actually call the vulnerable `template()` (**true VEX**) |
| 🔵 another `lodash` CVE → **`not_affected`** | you don't call *that* vulnerable function — de-prioritized |
| ○ `dangerouslySetInnerHTML` in an unused component | flagged **○ not reachable** (lower priority) |
| ✅ `NextResponse.redirect(new URL("/login", req.url))` | **not** flagged — same-origin redirect, not an open redirect |

Every finding carries a **CWE**, an **OWASP** category, and a **MITRE ATT&CK** technique.

### A single finding, in full

```
╭─ 1. 🔴 [CRITICAL] AWS access key committed to the repository ─────────────╮
│  .env.local:2                                                            │
│  CWE-798  ·  A07:2021  ·  ATT&CK T1552.001  ·  confidence: high           │
│  🎯 Reachable                                                            │
│                                                                          │
│  💡 Why this matters                                                     │
│  An AWS access key pair grants programmatic access to your cloud         │
│  account. Committed AWS keys are scraped automatically and can be used   │
│  to spin up servers (huge bills) or read your data within minutes.       │
│                                                                          │
│  🛠  How to fix it                                                        │
│  Deactivate and delete this key in the AWS IAM console immediately,      │
│  then issue a new one and store it in your host's secret manager.        │
╰──────────────────────────────────────────────────────────────────────────╯
```

### The cross-file taint flow

`req.body` in the route → through an **imported** helper → to a sink **in another file**:

```
🟠 [HIGH] xss.inner-html   app/api/products/route.ts:10
   req.body → paint() in lib/render.ts (param 1 → el.innerHTML) → innerHTML [in lib/render.ts]
```

### Enterprise output (also generated)

```bash
njordscan scan examples/vulnerable-shop --sbom sbom.json            # CycloneDX SBOM + VEX
njordscan scan examples/vulnerable-shop --format attack-navigator -o layer.json   # ATT&CK Navigator
njordscan scan examples/vulnerable-shop --format html -o report.html              # shareable HTML
```

Sample artifacts are committed here:
- [`sample-output/sbom.cdx.json`](vulnerable-shop/sample-output/sbom.cdx.json) — SBOM where each CVE
  has a VEX `analysis` (`exploitable` vs `not_affected` / `code_not_reachable`).
- [`sample-output/attack-navigator.json`](vulnerable-shop/sample-output/attack-navigator.json) — load
  into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see the heatmap.
- [`sample-output/report.html`](vulnerable-shop/sample-output/report.html) — the shareable report.

> The app under `vulnerable-shop/` is **intentionally insecure** and uses synthetic, fake
> credentials. Never deploy it.

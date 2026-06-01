# 🛡 NjordScan

**A security scanner for Next.js, React, and Vite apps — that explains every finding in plain English.**

NjordScan is built for developers who ship fast and aren't security experts. It finds the
issues that actually bite web apps — exposed secrets, XSS, dangerous dependencies, risky
config — and for **every** finding it tells you *why it matters* and *exactly how to fix it*,
with a corrected code example you can copy. **120+ rules** across the Next.js / React / Vite /
web / **AI-app** attack surface, each with a plain-English explanation — plus optional **live
(DAST) scanning** and an **MCP server** so your AI coding assistant can scan as you build.

> Status: **Beta.** The core scanner is stable and well-tested. No scanner catches everything —
> treat NjordScan as a strong safety net, not a guarantee.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install njordscan          # core install — small, no heavy deps, no build tools needed

njordscan scan .               # scan the current project
```

That's it. No account, no setup wizard, no "accept terms" prompt, and **nothing leaves your
machine** unless you explicitly ask for it.

```bash
njordscan scan .                       # human-friendly, educational report (default)
njordscan scan . --fix                 # apply safe, additive fixes (preview with --dry-run)
njordscan scan . --fail-on high        # exit 1 on any High/Critical — drop into CI as-is
njordscan scan . --diff origin/main    # only issues on lines this PR changed
njordscan scan . --url https://staging.myapp.com   # also dynamically scan a live app (DAST)
njordscan scan . --format html -o report.html   # pretty shareable report
njordscan scan . --format sarif -o out.sarif     # GitHub code scanning
njordscan explain xss.dangerously-set-inner-html # deep-dive on any rule
njordscan doctor                       # what's installed & working
njordscan update                       # refresh CVE data from OSV.dev
njordscan mcp                          # run as an MCP server for AI coding assistants
```

## What it finds

| Area | Examples |
|------|----------|
| **Secrets** | API keys, AWS keys, DB passwords, tokens — in code **and** `.env*` files; secrets exposed to the browser via `NEXT_PUBLIC_`/`VITE_` |
| **Taint tracking** | User input → dangerous sink, **across functions** and through **JSX `dangerouslySetInnerHTML`** (tree-sitter AST) |
| **XSS / DOM** | `innerHTML`, `document.write`, `javascript:` URLs, unsanitized markdown, `postMessage` without origin checks |
| **Injection** | `eval`, command injection, SQL/NoSQL injection, path traversal, prototype pollution |
| **Dependencies** | Known-vulnerable versions (bundled CVE/GHSA DB, refreshable from OSV.dev) and typosquatting |
| **Supply chain** | Dangerous `postinstall` scripts (`curl \| sh`, reverse shells), missing lockfiles |
| **Next.js** | Env leaks from `getServerSideProps`/API routes, wildcard CORS, open redirects in middleware, SVG/image foot-guns |
| **Vite** | `import.meta.env` secrets, `define` inlining, exposed dev server, prod sourcemaps |
| **Crypto / JWT** | Weak hashes, insecure randomness, hard-coded JWT secrets, `alg: none`, weak ciphers |
| **Cookies / auth** | Missing `httpOnly`/`secure`/`sameSite`, hard-coded session secrets, tokens in `localStorage` |
| **CORS / CSP / CSRF** | `*` + credentials, reflected origins, `unsafe-inline` CSP, missing CSRF on mutations |
| **Config & headers** | `next.config` foot-guns, disabled TLS verification, missing security headers |
| **Git hygiene** | A `.env` that's committed or not in `.gitignore` (the #1 way beginners leak secrets) |
| **🤖 AI / LLM apps** | Prompt injection, **LLM output → `eval`/SQL/`dangerouslySetInnerHTML`**, provider keys in client code, `dangerouslyAllowBrowser`, and **unauthenticated AI endpoints** (denial-of-wallet) |
| **🌐 Dynamic (DAST)** | With `--url`: live security headers, insecure cookies, reflected XSS, open redirects, stack-trace leaks, exposed AI endpoints |

Each finding maps to a CWE and OWASP category. Silence any line with a trailing
`// njordscan-ignore` comment.

## AI / LLM application security

Vibe coders are building AI apps — so NjordScan covers the risks unique to them, which most
scanners ignore: **prompt injection** (user input reaching a system prompt), **treating LLM
output as trusted** (model output flowing into `eval`, SQL, or `dangerouslySetInnerHTML`),
**provider keys shipped to the browser**, and **unauthenticated AI endpoints** that let anyone
run up your model bill (a "denial-of-wallet" attack). Each is explained in plain English.

## Dynamic scanning (DAST)

Point NjordScan at a running app to catch what only shows up at runtime:

```bash
pip install 'njordscan[dynamic]'
njordscan scan . --url https://staging.myapp.com
```

It checks real response headers (CSP/HSTS/X-Frame/…), cookie flags, reflected XSS, open
redirects, stack-trace leaks, and exposed AI endpoints. **Safe by design:** TLS verification
stays on, only benign/idempotent probes are sent (no state-changing payloads, no cost-incurring
AI calls), and it **refuses private/loopback hosts** unless you pass `--allow-private`.

## Use it with your AI coding assistant (MCP)

NjordScan is an [MCP](https://modelcontextprotocol.io) server, so assistants like Claude Code
and Cursor can scan the code they just wrote — and get the same plain-English findings + fixes:

```bash
claude mcp add njordscan -- njordscan mcp
```

Now your assistant can call `njordscan_scan` / `njordscan_explain` inline while you build.

## Fast PR feedback (`--diff`)

```bash
njordscan scan . --diff origin/main --fail-on high   # only fail on issues this PR introduced
```

Reports only findings on the lines your change touched — perfect for adopting NjordScan on an
existing codebase without fixing the whole backlog at once.

## Reachability — fix what's actually exploitable first

NjordScan builds an **import graph** from your framework's entrypoints (Route Handlers, API
routes, Server Actions, middleware, the client bundle) and marks each finding as **reachable or
not** — with the path and whether it runs **server-side** (higher risk) or **client-side**. This
is the "reachability"/ASPM technique commercial tools charge enterprise money for.

```
🟠 [HIGH] SQL query built by string concatenation   lib/db.ts:4
🎯 Reachable (server-side) from app/api/search/route.ts
```

The identical bug in unimported dead code is flagged **○ Not reachable (lower priority)**. Use
`njordscan scan . --reachable-only` to hide dead-code noise entirely. (Static analysis is a strong
signal, not a proof — "not reachable" means *lower priority*, never *ignored*.)

**It works for dependencies too (true VEX).** NjordScan doesn't just say "you have a vulnerable
package" — it analyzes which functions you actually import and call:

```
🎯 Reachable: your code calls the vulnerable `template` from `lodash`.        → stays High
✅ Lower priority: you import `lodash` but never call the vulnerable `template`. → not_affected
✅ Not reachable: `lodash` isn't imported in your code (transitive dependency). → not_affected
```

That reachability becomes a proper **VEX** (`affected` / `not_affected` + justification) right in
the CycloneDX SBOM — so the noise of "47 CVEs" collapses to the handful you can actually be hit by.

## Agentic AI fix-and-verify

Beyond the safe mechanical `--fix`, `--ai-fix` lets an AI patch deeper findings — but **NjordScan
verifies the patch actually worked before keeping it**: it applies the AI's change to a throwaway
copy, **re-scans**, and only accepts the fix if the issue is gone *and* no new issue appeared. If a
patch fails the re-scan, NjordScan **feeds the failure back to the model and retries** (a real
agentic loop) until it verifies or gives up — and tells you how many attempts it took.

```bash
njordscan scan . --ai-fix --ai-provider ollama --dry-run   # preview AI-verified patches
njordscan scan . --ai-fix --ai-provider ollama             # apply the verified ones
```

The AI never gets the last word — the scanner does.

## Threat intelligence & enterprise output

NjordScan speaks the language security teams use:

- **MITRE ATT&CK** — every rule is mapped to ATT&CK technique(s), shown inline and in SARIF.
  Export your app's attack surface as an **ATT&CK Navigator layer**:
  ```bash
  njordscan scan . --format attack-navigator -o layer.json   # load into ATT&CK Navigator
  ```
- **Exploit prioritization** — `njordscan update` pulls the **CISA KEV** catalog (CVEs *actively
  exploited in the wild*) and **EPSS** scores, so dependency findings tell you what to patch
  *first*: `🚨 ACTIVELY EXPLOITED (CISA KEV)` and `EPSS 79% 30-day exploit probability`.
- **SBOM** — a CycloneDX or SPDX bill of materials that also flags which components are vulnerable:
  ```bash
  njordscan scan . --sbom sbom.json --sbom-format cyclonedx
  ```
- **Scan history** — every scan is saved; see issues appear, get fixed, or linger:
  ```bash
  njordscan results              # list past scans
  njordscan results --compare first last   # what's new / fixed / still there
  ```

## Plain-English explanations (the whole point)

Every finding ships with an offline, built-in explanation — **no AI, no network, no config**:

```
🔴 [CRITICAL] AWS access key committed to the repository   .env.local:1

💡 Why this matters
   An AWS access key pair grants programmatic access to your cloud account.
   Committed AWS keys are scraped automatically and can be used to spin up
   servers (huge bills) or read your data within minutes of being pushed.

🛠  How to fix it
   Deactivate and delete this key in the AWS IAM console immediately, then
   issue a new one and store it in your host's secret manager / environment.
```

### Optional AI explanations (opt-in, your choice of engine)

Want a model to review each finding against *your* code? One flag — **off by default**:

```bash
njordscan scan . --explain-with-ai --ai-provider ollama   # local model: private & free
ANTHROPIC_API_KEY=... njordscan scan . --explain-with-ai --ai-provider claude
OPENAI_API_KEY=...    njordscan scan . --explain-with-ai --ai-provider openai
```

Defaults to **Ollama** (local) when no provider is named. For hosted providers, secrets are
**redacted from code before it's sent** (`--no-redact` to override). `--no-external` hard-blocks
any network call. Requires `pip install 'njordscan[ai]'`.

## Autofix

`--fix` applies only **provably-safe, additive** changes (it never rewrites your logic), and
shows you exactly what it did:

```bash
njordscan scan . --fix --dry-run   # preview a unified diff
njordscan scan . --fix             # apply
```

Currently auto-fixes `rel="noopener noreferrer"` on `target="_blank"` links and hardens
`.gitignore` against committed env files. More fixers over time.

## Adopt into an existing project (baseline)

Don't want to fix everything at once? Snapshot today's findings and only fail on **new** ones:

```bash
njordscan scan . --baseline .njordscan-baseline.json --update-baseline   # snapshot once
njordscan scan . --baseline .njordscan-baseline.json --fail-on high      # CI: only new issues fail
```

## Configure (`.njordscan.yml`)

```bash
njordscan init        # writes a starter .njordscan.yml
```

```yaml
min_severity: low
fail_on: high
ignore: ["**/legacy/**"]
disable_rules: [react.unsafe-target-blank]   # rules you've reviewed
severity: { crypto.weak-hash: high }         # bump/lower a rule
baseline: .njordscan-baseline.json
```

## CI / pre-commit

GitHub Action:

```yaml
- uses: nimdy/njordscan@v2
  with:
    path: .
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: njordscan.sarif }
```

pre-commit:

```yaml
repos:
  - repo: https://github.com/nimdy/njordscan
    rev: v2.0.0b1
    hooks: [{ id: njordscan }]
```

Exit codes: `0` = clean (or below `--fail-on`), `1` = findings met the gate, `2` = scan error.

## Command reference

| Command | What it does |
|---------|--------------|
| `njordscan scan [dir]` | Scan a project (default `.`) — see flags below |
| `njordscan explain <rule>` | Deep-dive a rule (why + fix); no argument lists every rule |
| `njordscan init [dir]` | Write a starter `.njordscan.yml` |
| `njordscan update [dir]` | Refresh the CVE database (OSV) + exploit intel (CISA KEV, EPSS) |
| `njordscan results [dir]` | Browse past scans and diff them over time |
| `njordscan doctor` | Show what's installed and working |
| `njordscan mcp` | Run as an MCP server for AI coding assistants |
| `njordscan version` | Show the version |

Key `scan` flags: `--fix` / `--ai-fix` / `--dry-run`, `--reachable-only`, `--fail-on`, `--min-severity`,
`--format` (terminal/json/sarif/html/attack-navigator), `-o`, `--sbom` / `--sbom-format`,
`--diff [ref]`, `--baseline` / `--update-baseline`, `--only` / `--skip` (comma-separated ok),
`--url` / `--allow-private`, `--explain-with-ai` / `--ai-provider`, `--mode quick`, `--config`,
`--quiet` / `-v`. Run `njordscan scan --help` for the full list. Silence one line with a trailing
`// njordscan-ignore` comment.

**Exit codes:** `0` = clean (or below `--fail-on`) · `1` = a finding met `--fail-on` · `2` = scan error.

## Documentation

Full guides live in **[docs/](docs/)**:

- [Getting started](docs/getting-started.md) · [Configuration](docs/configuration.md) ·
  [CI/CD & PRs](docs/ci-cd.md)
- [Dynamic scanning (DAST)](docs/dynamic-scanning.md) · [AI features](docs/ai-features.md) ·
  [AI assistants (MCP)](docs/ai-assistant-mcp.md)
- [Troubleshooting & FAQ](docs/troubleshooting.md) · **[Rules catalog (120+)](docs/RULES.md)**

## Design principles

- **Installs clean, everywhere.** Pure-Python + prebuilt wheels only. No numpy, no system libraries, no build step.
- **Never crashes on your code.** One weird file can't take down a scan; detectors fail isolated.
- **Low false positives.** A clean app produces zero findings — so you can trust a clean result.
- **Private by default.** Nothing is uploaded unless you pass an AI flag or `--url`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup and how to add a rule, and
[HANDOFF.md](HANDOFF.md) for the full architecture.

```bash
pip install -e '.[dev]'
pytest -q          # 55 tests
```

## License

MIT

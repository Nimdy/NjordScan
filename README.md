# 🛡 NjordScan

**A security scanner for Next.js, React, and Vite apps — that explains every finding in plain English.**

NjordScan is built for developers who ship fast and aren't security experts. It finds the
issues that actually bite web apps — exposed secrets, XSS, dangerous dependencies, risky
config — and for **every** finding it tells you *why it matters* and *exactly how to fix it*,
with a corrected code example you can copy. Over **100 rules** across the Next.js / React /
Vite / web attack surface, each with a plain-English explanation.

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
njordscan scan . --format html -o report.html   # pretty shareable report
njordscan scan . --format sarif -o out.sarif     # GitHub code scanning
njordscan explain xss.dangerously-set-inner-html # deep-dive on any rule
njordscan doctor                       # what's installed & working
njordscan update                       # refresh CVE data from OSV.dev
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

Each finding maps to a CWE and OWASP category. Silence any line with a trailing
`// njordscan-ignore` comment.

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

## Design principles

- **Installs clean, everywhere.** Pure-Python + prebuilt wheels only. No numpy, no system libraries, no build step.
- **Never crashes on your code.** One weird file can't take down a scan; detectors fail isolated.
- **Low false positives.** A clean app produces zero findings — so you can trust a clean result.
- **Private by default.** Nothing is uploaded unless you pass an AI flag.

## Development

```bash
pip install -e '.[dev]'
pytest -q
```

## License

MIT

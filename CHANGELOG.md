# Changelog

All notable changes to NjordScan are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## 2.0.0b1 — clean-room rebuild (beta)

NjordScan 2.0 is a complete rewrite focused on **trustworthiness for developers who aren't
security experts**: it installs cleanly, never crashes on your code, produces zero false
positives on a clean app, and explains every finding in plain English.

### Added
- **120+ rules** across Next.js / React / Vite / web / AI-app security, each with a plain-English
  "why this matters" + "how to fix it" + a secure code example, mapped to CWE and OWASP.
- **Tree-sitter taint tracking** that follows user input to dangerous sinks **across functions**,
  **across files (interprocedural)** — through an imported helper into a sink in another module —
  and through **JSX `dangerouslySetInnerHTML`**.
- **Secrets** detection in code *and* committed `.env*` files, with output masking.
- **Dependency** scanning against a bundled CVE/GHSA database, refreshable from OSV.dev
  (`njordscan update`).
- **Supply-chain** checks: dangerous `postinstall` scripts (in your code and **in installed
  dependencies**), missing lockfiles, and **install-script change detection** — NjordScan baselines
  each dependency's install scripts and flags any that are new or changed since the last scan, so a
  freshly-compromised package version is caught on redeploy without waiting for an advisory.
- **Git-hygiene** detector — catches a `.env` that is committed or not in `.gitignore`.
- **AI / LLM application security** (`ai.*`): prompt injection, LLM output flowing to a sink or
  rendered as HTML, provider keys in client code, `dangerouslyAllowBrowser`, unauthenticated AI
  endpoints (denial-of-wallet), and secrets/PII sent to a model.
- **Dynamic scanning (DAST)** via `--url` (`[dynamic]` extra): live security headers, cookie
  flags, reflected XSS, open redirects, verbose errors, exposed AI endpoints. TLS verification
  stays on; private/loopback hosts are refused unless `--allow-private`; only benign probes.
- **Safe autofix** (`--fix`, `--dry-run`) for provably-safe, additive changes.
- **`--diff [ref]`** PR mode: report only findings on changed lines.
- **Baseline** (`--baseline`, `--update-baseline`) to adopt into an existing repo.
- **`.njordscan.yml`** config file + `njordscan init`.
- **Reachability analysis** — an import graph rooted at framework entrypoints (Route Handlers, API
  routes, Server Actions, middleware, client bundle) marks each finding reachable / not-reachable,
  server- vs client-side, with the path. `--reachable-only` hides unreachable dead code.
- **Dependency reachability (true VEX)** — usage analysis (`core/usage.py`) determines whether you
  actually *call the vulnerable function* of a CVE'd package: `exploitable` if you call it,
  `not_affected` (code_not_reachable) if you import the package but not the vulnerable symbol, or
  `not_affected` (code_not_present) if it's never imported. Drives a CycloneDX **VEX** in the SBOM
  and de-prioritizes unreachable dependency CVEs.
- **Agentic AI fix-and-verify** (`--ai-fix`) — an AI patches code findings, and NjordScan **verifies
  each patch by re-scanning a copy** (issue gone + no regressions) before accepting it; failed
  patches are **fed back to the model and retried** (an iterative agentic loop).
- **MITRE ATT&CK** mapping on every rule (shown inline + in SARIF), with an **ATT&CK Navigator
  layer** export (`--format attack-navigator`) of your app's attack surface.
- **Exploit prioritization** — `njordscan update` pulls the **CISA KEV** catalog (actively-exploited
  CVEs, which bump the finding to critical) and **EPSS** scores (30-day exploit probability).
- **SBOM** generation (CycloneDX 1.5 / SPDX 2.3) that correlates components with the CVE database.
- **Scan history** + the `results` command (list past scans, diff new/fixed/persistent over time).
- **Reports**: rich terminal, JSON, SARIF 2.1.0 (with taint code flows + ATT&CK tags), HTML, and ATT&CK Navigator.
- **MCP server** (`njordscan mcp`) so AI coding assistants (Claude Code, Cursor) can scan inline.
- **Hybrid AI explanations** (`--explain-with-ai`): offline by default; opt-in local Ollama or
  Claude/OpenAI with code redaction and a consent notice.
- **CI**: GitHub composite Action, pre-commit hook, and a CI workflow.
- `njordscan doctor` for a health check; correct, documented exit codes (0 / 1 / 2).

### Changed from 1.x
- Single-source packaging (`pyproject.toml`); a small, pure-Python core install with **no numpy or
  other heavy/system dependencies**. AI and dynamic features live in optional extras.
- `--fail-on` now works on its own (1.x required `--ci`).

### Removed
- The crash-on-import "AI/behavioral/threat-intelligence" subsystems, the broken SBOM command, the
  interactive `legal --accept` gate, and the unsigned plugin loader from 1.x. Their *working* value
  was reimplemented; their dead weight and security risks were dropped.

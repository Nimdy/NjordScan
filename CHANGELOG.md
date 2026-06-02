# Changelog

All notable changes to NjordScan are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## 2.0.0b2 — beta

### Added
- **`njordscan monitor` — a local-first operational security dashboard.** Register multiple
  projects (folders, git URLs, live URLs); NjordScan **re-scans each on a schedule** (hourly /
  daily / weekly), tracks findings **appear / get fixed / regress** over time (a trend sparkline per
  project), and **alerts when a new critical/high shows up** — diffing each scan against the last so
  it never re-alerts on issues you've already seen. Private and local: no account, no cloud, all
  state under `~/.njordscan/monitor`. Drill into any project for its scan timeline + new/fixed diff.
  An optional `docker/monitor.compose.yml` runs it always-on.
- **`njordscan gui`** — a local web **scan studio**. Point it at a local folder, a git URL
  (shallow-cloned then deleted), or a live URL (DAST) and explore the findings + attack paths in
  the browser: filter by severity, expand a finding for the plain-English why/how-to-fix, walk an
  attack-path kill chain. Same engine as the CLI; dependency-free (stdlib server + one offline HTML
  page). Binds to localhost only, runs scans in-process (NjordScan only *reads* a target).

### Security
- **`gui` + `monitor` are CSRF/rebinding-hardened.** The local servers reject cross-origin
  state-changing requests (a malicious page can't drive a scan or register a project at
  `127.0.0.1`) and only answer requests with a localhost `Host` (DNS-rebinding guard). Same-origin
  use and non-browser clients are unaffected; opt into network exposure with `--host 0.0.0.0`.

### Fixed (carried over from the post-2.0.0b1 hardening)
- **SSRF false positives** — a same-origin/relative `fetch(`/api/...`)` is no longer flagged as
  SSRF (only a dynamic/attacker-controlled host is).
- **Dev-only files de-prioritized** — findings in `scripts/`, build tooling, and tests are capped
  to LOW and annotated (never hidden), so a local setup script doesn't read like an app vuln.

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

#### Advanced analysis (the "how do I actually get hacked?" layer)
- **Attack-path synthesis** — instead of a flat list, NjordScan correlates findings into the
  ranked, plain-English **kill chains** an attacker would walk (ordered along the MITRE kill chain,
  scored 0–100 with the factors shown, each step citing a real `file:line`), and marks the single
  **★ break-the-chain** step that collapses the whole path. Renders in terminal/JSON/SARIF/HTML and
  the MCP response. Deliberately conservative — unrelated or dead-code findings never form a path.
- **Data-egress tracer (sensitivity-labeled taint)** — runs the taint engine in reverse: follows a
  *named* sensitive value (an env secret, a credential) to where it **leaves the trust boundary** —
  a log, an HTTP response, browser storage, or a third-party SDK (`dataflow.*` rules). Crosses the
  label with reachability so a secret whose egress runs in **client code** is escalated to critical
  ("bundled into the JS shipped to every visitor").
- **SQL injection by data flow** (`sqli.tainted-query`) plus idiomatic Next.js App Router source
  detection (`new URL(req.url).searchParams.get()`), so the flagship chains fire on real code.
- **🤖 AI red-teamer** (`--ai-attack-paths`) — an LLM proposes novel multi-step attack chains, and
  the deterministic engine **verifies every step and link against your real findings/reachability**,
  discarding anything it can't ground. The model can recombine proven facts; it cannot invent a
  vulnerability. Opt-in, offline-capable via Ollama; outputs show the engine-confirmed evidence.
- **🔑 Keystone (temporal analysis)** — in `--diff` mode, names the change that *completed* a
  pre-existing kill chain: it re-scans the tree before the change and reports a chain that exists
  after-but-not-before, attributing each pre-existing link to the commit/author that planted it
  (via `git blame`). Zero LLM in the verdict — a set-difference over two real git trees.
- **Self-updating threat intel** — `njordscan update` also refreshes detection **rules + patterns**
  from a configurable JSON feed (no reinstall), and a new **lockfile-integrity tamper detection**
  flags a pinned dependency whose *same version* resolves to *different content* on redeploy.
- **Simulation lab** (`simulation-lab/`) — a self-contained Dockerized **purple-team range**: a
  NjordScan container scans deliberately-vulnerable target services statically *and* live (DAST)
  over the container network, plus a red-team exploit playbook and a blue-team mini-SIEM, so
  `make purple` runs the full loop — NjordScan predicts the attack paths, the red team proves them
  by exploiting the live targets, and the blue team detects the traffic. A **segmented internal
  tier** (its own Docker network, no route from the attacker) adds a real **lateral-movement**
  scenario: the attacker must pivot through the web tier's RCE to reach the customer datastore
  (`make pivot`), and the blue team flags the landing CRITICAL. (Repo tooling; not part of the
  pip package.)

### Changed from 1.x
- Single-source packaging (`pyproject.toml`); a small, pure-Python core install with **no numpy or
  other heavy/system dependencies**. AI and dynamic features live in optional extras.
- `--fail-on` now works on its own (1.x required `--ci`).

### Removed
- The crash-on-import "AI/behavioral/threat-intelligence" subsystems, the broken SBOM command, the
  interactive `legal --accept` gate, and the unsigned plugin loader from 1.x. Their *working* value
  was reimplemented; their dead weight and security risks were dropped.

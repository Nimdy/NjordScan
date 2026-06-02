# 🛡 NjordScan

[![CI](https://img.shields.io/github/actions/workflow/status/Nimdy/NjordScan/ci.yml?branch=main&label=CI)](https://github.com/Nimdy/NjordScan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Nimdy/NjordScan/blob/main/LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/njordscan?label=PyPI)](https://pypi.org/project/njordscan/)
[![Status: beta](https://img.shields.io/badge/status-beta-orange.svg)](https://github.com/Nimdy/NjordScan#readme)

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

# install the 2.0 beta straight from source (works today):
pip install 'git+https://github.com/Nimdy/NjordScan.git@v2'

njordscan scan .               # scan the current project
```

That's it. No account, no setup wizard, no "accept terms" prompt, and **nothing leaves your
machine** unless you explicitly ask for it. The core install is small and pure-Python — no
numpy, no system libraries, no build tools.

> **Installing from PyPI:** once 2.0 is published, use `pip install --pre njordscan` — the
> `--pre` is required while 2.0 is in beta (a plain `pip install njordscan` would skip it).
> **Live DAST** (`--url`) and **AI features** each add one small optional dependency; pull them
> in with `pip install 'njordscan[dynamic,ai]'` (or `pip install '.[dynamic,ai]'` from a source
> checkout). Plain static scanning needs none of this.

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
| **Taint tracking** | User input → dangerous sink, **across functions, across files (interprocedural)**, and through **JSX `dangerouslySetInnerHTML`** (tree-sitter AST) |
| **XSS / DOM** | `innerHTML`, `document.write`, `javascript:` URLs, unsanitized markdown, `postMessage` without origin checks |
| **Injection** | `eval`, command injection, SQL/NoSQL injection, path traversal, prototype pollution |
| **Dependencies** | Known-vulnerable versions (bundled CVE/GHSA DB, refreshable from OSV.dev) and typosquatting |
| **Supply chain** | Dangerous `postinstall` scripts (`curl \| sh`, reverse shells) in your code **and in installed dependencies**; **catches a compromised package on redeploy** by flagging install scripts that are *new or changed since your last scan*; missing lockfiles |
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

## 🎯 Attack paths — it tells you *how you get hacked*, not just what's wrong

Every other scanner hands you a flat list — "40 issues, good luck." NjordScan does something
no other free tool does: it **correlates your findings into the actual multi-step attack an
adversary would walk**, as a plain-English story, scored by real-world exploitability, with the
single cheapest place to **break the chain**.

```
🎯 Attack paths  ·  how these issues chain into a real breach

╭─ path-1  Cloud/account pivot: server access → harvested secret ───────────────╮
│  🔴 score 100 · critical                                                      │
│  Impact: Compromise of external systems the leaked credential unlocks         │
│                                                                               │
│  ★ 1. [Execution] Server-side code/query execution   lib/db.ts:7              │
│        Untrusted input reaches a query/eval — an attacker can run code or      │
│        queries on the server.                                                  │
│    2. [Credential Access] A real secret is sitting right there   .env.local:2 │
│        An AWS access key committed to the repo is within reach of that         │
│        primitive.                                                             │
│    3. [Lateral Movement] Pivot beyond the app with stolen keys   .env.local:2 │
│        With the key, the attacker authenticates to your cloud — the blast      │
│        radius now extends past this app.                                       │
│                                                                               │
│  🛠  Break the chain at step 1 — parameterise the query / stop running          │
│      attacker-controlled input (lib/db.ts:7). Fixing that one thing stops it.  │
│  Why this scores 100: critical finding; server-side reachable; reaches a       │
│  concrete impact; exposes a credential (blast radius); distinct weaknesses     │
│  align.                                                                        │
╰───────────────────────────────────────────────────────────────────────────────╯
```

This is the part a non-expert actually needs: **which of your forty findings line up into a
breach, and the one fix that collapses it.** It's powered entirely by signals NjordScan already
computes — taint data-flow, reachability from real framework entrypoints, exposed secrets, and
live exploit intel (CISA KEV/EPSS) — so the chains are grounded in your actual code, not guessed.

It's deliberately **conservative and honest**, not dramatic for its own sake: the score factors
are always shown (never a magic number), a path's band is **capped to the worst real finding**,
every step cites a real `file:line`, and the engine refuses to invent connections — it won't
stitch an auth gap on one route to an injection on an unrelated route, won't call a server-side
DOM write "XSS in your users' browser," and won't pivot off a test-fixture or already-public
secret. Unrelated and dead-code findings produce **no** path. Attack paths appear in the terminal
report and in the `--format json` / `sarif` / `html` output (`attack_paths`) — and in the MCP
response, so your AI assistant gets the kill chain too.

## 🔐 Data-leak tracing — it follows your *secrets out*, not just attacks in

Every scanner traces attacker input flowing *into* a dangerous sink. NjordScan also runs the same
data-flow engine **in reverse**: it follows a **named sensitive value** — an environment secret
(`process.env.STRIPE_SECRET_KEY`), a credential (`passwordHash`, `accessToken`) — to the moment it
**leaves your trust boundary**: a log, an HTTP response, the browser, or a third-party SDK.

```
🟠 [HIGH] A secret or credential is sent in an HTTP response   app/api/login/route.ts:42

   Data flow (sensitive value → boundary exit):
        source: user.passwordHash (lib/db.ts:8)
          ↓
          sink: NextResponse.json(...) (app/api/login/route.ts:42)

💡 Why: anything in a response is readable by the user in the devtools Network tab — returning a
   whole DB row ships the password hash to the client.
```

It carries a **typed data label** through the flow (no other SAST taint engine does this), so it
can say *what* leaked and *where it went* in words a non-expert gets: *"your `STRIPE_SECRET_KEY`
flows into a Sentry breadcrumb — you're shipping a secret to a third party."* And it crosses the
label with reachability: a secret whose egress runs in **client code** is escalated to **CRITICAL**
— *"this is bundled into the JavaScript shipped to every visitor; anyone can read it in devtools"* —
and surfaces as a data-egress **attack path**.

It's tuned for **zero theater**: labels come only from a literal `process.env` access or a
high-precision credential name (generic words like `token`/`key`/`email` never match), public-by-
design vars (`NEXT_PUBLIC_*`, `NODE_ENV`) are excluded, and it won't flag the very redaction it
recommends (`secret.slice(-4)`, `secret.length`, `secret === x`). Nothing is flagged unless it
actually reaches an exit.

## 🤖 AI red-teamer — the LLM proposes, the engine *verifies* (it cannot hallucinate)

```bash
njordscan scan . --ai-attack-paths --ai-provider ollama   # local & private, or claude/openai
```

The built-in attack-path templates find the chains we hand-coded. An LLM can recombine the *same
confirmed findings* into **novel, longer, cross-category attack chains** the templates never
enumerate — an attacker's imagination over a fixed set of facts. The problem with LLMs is they
make things up. So NjordScan treats the model as a **suspect**, not an oracle:

- it may only reference findings that **actually exist** (by id) — invented steps are dropped;
- **every link it claims between two steps is re-checked against the real reachability, roles, and
  data-flow** — and the chain is thrown out if any link can't be grounded;
- what survives is shown with its proof: *"✓ Verified links (engine-confirmed, not the model's
  word)."*

```
🤖 AI-discovered attack paths · the model proposed these; NjordScan verified every step

╭─ ai-path-1  Unauthenticated takeover → secret harvest → exfiltration ─────────╮
│  🔴 score 100 · critical   🤖 AI-discovered · every step verified             │
│  1. [Initial Access]   Auth guard hard-wired to return true   app/api/chat/route.ts:3
│  2. [Execution]        User input flows into a database query  lib/db.ts:7    │
│  3. [Credential Access] AWS access key committed to the repo   .env.local:2   │
│  4. [Exfiltration]     A secret is sent to a third-party SDK   lib/log.ts:4   │
│  ✓ Verified links (engine-confirmed, not the model's word):                   │
│     • auth-bypass → SQLi: both reachable from the same entrypoint             │
│     • SQLi → secret: the server-side primitive can read the exposed secret    │
│     • secret → exfiltration: the exposed credential is what gets carried out  │
╰───────────────────────────────────────────────────────────────────────────────╯
```

This is the part that should make you trust it: it's the **"LLM proposes, deterministic engine
disposes"** pattern made visible. The model contributes *creativity* (the 4-step chain across auth,
injection, secrets, and a logging SDK that no single template covers); the engine contributes
*ground truth* (every hop is a real finding linked by a real, checked relationship). A hypothesized
step that doesn't map to your code, or a link the engine can't confirm, is **silently discarded** —
so the AI literally cannot invent a vulnerability. Opt-in, **off by default**, and **offline-capable**
via a local model.

## 🔑 Keystone commit — the change that *armed* a pre-existing attack chain

```bash
njordscan scan . --diff origin/main    # keystone analysis is on by default in --diff mode
```

Every PR scanner on earth is **diff-local**: it flags issues whose lines you touched. None
can see the most dangerous commit of all — the innocent-looking one that **completes a kill
chain whose other links were planted months ago by other people** — because none own a
whole-repo attack-chain model. NjordScan does, so it can ask a question nobody else can:
*given everything already in the repo, did **this** change arm a latent chain?*

It reconstructs the tree **before** your change, re-runs the exact same attack-path synthesis,
and compares. A chain that exists *after* but not *before*, with one link you just added and
one that pre-existed, is a chain your change **armed** — and each pre-existing link is dated by
`git blame`:

```
🔑 Keystone · this change completed 1 pre-existing attack path

╭─ Account/data takeover via unauthenticated injection   score 98 · critical ──╮
│  ★ 1. [Initial Access] No authentication on the entry point   route.ts:1
│        ← the link this change added
│    2. [Execution] Attacker-controlled data hits a query   route.ts:5
│        planted by Alice on 2026-03-02
│  🔑 Step 1 is new in this change; the rest was already in the repo (planted by
│     Alice). Neither change was a vulnerability alone — together they're a
│     complete chain. Revert or guard the new link to disarm it.
╰───────────────────────────────────────────────────────────────────────────────╯
```

A vulnerability stops being an event and becomes a **4D object** — repo state over time, with a
git birthday and an assembling cast. The grounding is **bulletproof and has no model in it**:
*"a new critical chain exists"* is a literal set-difference between two deterministic scans of
two real git trees, reproducible by anyone who checks out the refs; *"this link pre-existed,
planted by Alice"* is `git blame` on the unchanged line — with a self-correcting guard that
demotes a moved/reformatted line so an author is never falsely accused. Perfect for a CI PR gate.

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

## Catch a compromised dependency on redeploy

Most npm supply-chain attacks work by sneaking a malicious `postinstall` into a patch release of a
package you already trust — and they run on `npm install`, before your app even starts, often with
no advisory for days. NjordScan scans your **installed dependencies** (`node_modules`) and:

- flags any dependency whose install script does something dangerous (`curl | sh`, reverse shell,
  reads `~/.ssh`/`~/.npmrc`, decodes an obfuscated payload) — **no advisory required**;
- remembers each dependency's install scripts and, on your next scan, flags any that are **new or
  changed** — so a freshly-compromised version is caught the moment it lands:

```
🔴 [CRITICAL] Dependency 'left-pad' added a new 'postinstall' install script since your last scan
             — investigate before deploying (possible compromised update).
```

- records each pinned package's **lockfile integrity hash** and flags it if the *same version* ever
  resolves to **different content** — the signature of a re-published / poisoned tarball or a
  compromised mirror, even when nothing else in `package.json` changed:

```
🔴 [CRITICAL] left-pad@1.3.0 now has a DIFFERENT integrity hash than your last scan — the same
             version resolves to different content (possible tampering / re-publish).
```

Run it in CI after `npm ci`, or on every redeploy. (Honest scope: this catches the *common* attack
patterns — malicious/obfuscated install behavior and content tampering — which is how most real npm
compromises work; a sophisticated backdoor hidden in legit-looking code can still evade behavioral
analysis.)

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
- **Self-updating threat intel** — `njordscan update` refreshes advisories (OSV), exploit intel
  (KEV/EPSS) **and the detection rules + patterns themselves** from a signed-by-host JSON feed, so
  new rules ship **without a reinstall**. Scans nudge you when the data goes stale, and `njordscan
  doctor` shows exactly how fresh it is:
  ```bash
  njordscan update               # advisories + exploit intel + fresh rules/patterns
  NJORDSCAN_RULES_FEED=https://my.host/feed.json njordscan update   # self-host the feed
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

## See it in action

**[examples/vulnerable-shop](examples/)** is a realistic deliberately-insecure Next.js app —
`njordscan scan examples/vulnerable-shop` finds 30 issues spanning secrets, cross-file taint,
AI-app security, supply-chain, and dependency **VEX**, each explained with a fix. The full captured
report and sample SBOM/Navigator artifacts are committed there.

**[simulation-lab/](simulation-lab/)** goes further — a self-contained Dockerized **purple-team
range**. One command (`make purple`) runs the full loop: NjordScan *predicts* the attack paths in
a live target, a red-team container *proves* them by exploiting the running service over the
network (real RCE, denial-of-wallet), and a blue-team mini-SIEM *detects* the same traffic in the
access logs. It's both the proof and the test bed — and a usable training range in its own right.

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, the project map, and how to add a rule.

```bash
pip install -e '.[dev]'
pytest -q          # 171 tests
```

## License

MIT

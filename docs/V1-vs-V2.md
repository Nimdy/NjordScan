# NjordScan V1 vs V2 — Complete Feature Comparison

## 1. Executive Summary

V2 is a focused, honest rewrite that kept NjordScan's genuinely working core — taint-based XSS tracking, secrets, supply-chain, dependency CVE matching, config analysis, and the Terminal/JSON/SARIF/HTML report stack — and made every piece of it actually work end-to-end, while adding a real rule library (121 rules + 127 patterns in YAML), an MCP server for AI assistants, provably-safe autofix, baseline/diff (PR) scanning, a shareable `.njordscan.yml` config, and a 60-test suite. Genuinely new in V2: MCP integration, autofix/dry-run, baseline + git-diff mode, the three-tier (offline → Ollama → remote) privacy-first AI explanation system, and shipped CI assets (`action.yml`, pre-commit hook). What was actually dropped is narrow: SBOM generation, results-history/compare/trends, the plugin system + marketplace, the `learn`/`community`/`setup`/`fix`(legacy)/`configure` commands, MITRE ATT&CK / threat-intel / behavioral-analysis intelligence, and the auto-updating CVE feed (replaced by a simpler OSV.dev `update`). Crucially, much of V1's apparent surface area was illusory: roughly half its flags were `partial` (accepted but not wired up), several headline subsystems were `stub`, `broken`, or `crash-on-import` (SBOM, fuzzing engine, behavioral analyzer, intelligence orchestrator) — so V2 is smaller on paper but larger in real, shipping capability.

---

## 2. Side-by-Side Tables by Area

### CLI Commands

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| `scan` (core scan) | working | working | 🔁 Parity |
| `explain` (rule/vuln explainer) | partial (impl unclear) | working (121-rule explorer) | ✅ Improved |
| `init` / config scaffolding | partial (`configure --init` only) | working (`init` writes `.njordscan.yml`) | ✅ Improved |
| `doctor` (diagnostics) | working | working (richer: detectors/rules/patterns/tree-sitter/AI) | 🔁 Parity |
| `update` (vuln data) | partial (relies on feeds that may be absent) | working (OSV.dev → user cache, stdlib only) | ✅ Improved |
| `version` | working | working | 🔁 Parity |
| `mcp` (MCP stdio server) | — | working | ➕ New in V2 |
| `setup` (wizard) | stub ("not yet available") | — | 🗑️ Dropped-but-was-stub |
| `configure` (init/validate/show/export) | partial (`--interactive` stub) | folded into `init` + `.njordscan.yml` | ✅ Improved (real part kept) |
| `results` (browse/list/compare/trends) | partial (`--list-scans` only; rest stub) | — | ❌ Dropped (list-scans was real) |
| `fix` (interactive remediation) | stub ("not yet available") | replaced by `scan --fix` | 🗑️ Dropped-but-was-stub |
| `legal` (disclaimer mgmt) | working | — | ❌ Dropped |
| `plugins` (list/install/create/…) | partial (most features incomplete) | — | ❌ Dropped (partly real) |
| `community` | stub ("not yet available") | — | 🗑️ Dropped-but-was-stub |
| `learn` (tutorials) | partial (`--topic` works; interactive stub) | — | ❌ Dropped (topic info was real) |
| `cache stats` / `cache clear` | working | — (caching internal, no CLI) | ❌ Dropped |

### CLI Flags (on `scan`)

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| `--format` (terminal/json/sarif/html…) | working | working | 🔁 Parity |
| `--output / -o` | working | working | 🔁 Parity |
| `--mode` (quick/standard/deep) | working | working (quick skips taint+deps) | 🔁 Parity |
| `--framework` (force detection) | working | auto-detection only (no force flag) | ❌ Dropped (minor) |
| `--severity` / `--min-severity` | working | working | 🔁 Parity |
| `--verbose / -v` | working | working | 🔁 Parity |
| `--quiet / -q` | working | working | 🔁 Parity |
| `--no-cache` / cache flags | working | — (no user cache toggle) | 🗑️/❌ minor |
| `--fail-on` (CI gating) | working | working | 🔁 Parity |
| `--ci` mode | working | superseded by `action.yml` + `--fail-on` | ✅ Improved |
| `--skip` / `--only` (module select) | working | working (detector IDs) | 🔁 Parity |
| `--timeout` | working | — | ❌ Dropped (minor) |
| `--threads` | working | — (async, no flag) | 🗑️ minor |
| `--no-color` | working | — (Rich auto-detects) | 🗑️ minor |
| `--web` / `--url` (DAST) | working | working (`--url`, SSRF-safe) | ✅ Improved |
| `--enhanced / -e` | working | — (single unified scanner) | 🗑️ Dropped (redundant) |
| `--ai-enhanced` | partial | replaced by `--explain-with-ai` | ✅ Improved |
| `--explain-with-ai` / `--ai-provider` | partial (with fallback) | working (3-tier, ollama default) | ✅ Improved |
| `--behavioral-analysis` | partial | — | 🗑️ Dropped (backed by crash-on-import) |
| `--threat-intel` | partial (impl unknown) | — | 🗑️ Dropped (was partial/unwired) |
| `--community-rules` | partial | — | 🗑️ Dropped-but-was-partial |
| `--theme` | partial (minimal) | — | 🗑️ Dropped-but-was-partial |
| `--interactive` | stub | — | 🗑️ Dropped-but-was-stub |
| `--quality-gate` | partial (accepted, unused) | — | 🗑️ Dropped-but-was-stub |
| `--show-progress` | partial (unclear) | — | 🗑️ Dropped-but-was-partial |
| `--include-remediation` | partial (not fully impl) | always-on (why/fix in every finding) | ✅ Improved |
| `--executive-summary` | partial | — | 🗑️ Dropped-but-was-partial |
| `--memory-limit` | partial (enforcement unclear) | — | 🗑️ Dropped-but-was-partial |
| `--custom-rules` | partial | data-driven YAML rules + `disable_rules` | ✅ Improved |
| `--false-positive-filter` | partial | inline `njordscan-ignore` + entropy/confidence | ✅ Improved |
| `--trend-analysis` | partial | — | 🗑️ Dropped-but-was-partial |
| `--sbom` / `--sbom-format` | partial (needs deps module) | — | ❌ Dropped (see SBOM) |
| `--pentest` | working | — (replaced by non-invasive DAST) | ❌ Dropped |
| `--brief` | — | working | ➕ New in V2 |
| `--fix` / `--dry-run` | — | working | ➕ New in V2 |
| `--baseline` / `--update-baseline` | — | working | ➕ New in V2 |
| `--diff [ref]` (PR mode) | — | working | ➕ New in V2 |
| `--ignore` (globs) | — (skip modules only) | working | ➕ New in V2 |
| `--allow-private` (DAST SSRF override) | — | working | ➕ New in V2 |

### Detection / Static Analysis

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| XSS taint tracking (tree-sitter AST) | working | working (+ cross-function, JSX attrs, open redirect) | ✅ Improved |
| SQL injection detection | working | covered by taint sinks + patterns | 🔁 Parity |
| Command injection detection | working | working (taint child_process sinks) | 🔁 Parity |
| Secrets detection | working | working (entropy-weighted) | ✅ Improved |
| Static line-by-line regex detector | working (code_static) | working (`static`, comment/literal-aware) | 🔁 Parity |
| Configuration security analysis | working | working (`configs`: next/vite, never executed) | 🔁 Parity |
| Supply-chain attack detection | working (40+ patterns) | working (lifecycle scripts, lockfile, registry) | 🔁 Parity |
| Dependency vuln scanning | working (npm audit, dep graph) | working (OSV + seed DB, semver ranges) | 🔁 Parity |
| Typosquatting detection | (part of supply chain) | working (Levenshtein vs popular pkgs) | ✅ Improved |
| AI endpoint detection | working (7 providers, prompt-injection) | working (DAST: unauth AI endpoints) | 🔁 Parity |
| Git hygiene (tracked .env) | — | working (`git-hygiene`) | ➕ New in V2 |
| Data-driven pattern engine | — (hardcoded) | working (127 YAML patterns, filters) | ➕ New in V2 |
| Next.js framework analysis | partial | working (nextjs:10 rules + configs) | ✅ Improved |
| React framework analysis | partial | working (react:6 rules) | ✅ Improved |
| Vite framework analysis | partial (minimal) | working (vite:9 rules) | ✅ Improved |
| Vulnerability classifier (OWASP/CWE) | working | per-rule CWE/OWASP mapping (always-on) | 🔁 Parity |
| Rules engine | working | working (data-driven YAML) | 🔁 Parity |
| False positive filter | partial | working (inline ignore + confidence) | ✅ Improved |

### Dynamic / DAST

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| Runtime/DAST testing (live app) | working (`runtime.py`, `dast_engine.py`) | working (`runtime`, SSRF-safe, TLS-on) | ✅ Improved |
| Security headers analysis | working (aiohttp) | working (httpx, headers + cookie flags) | 🔁 Parity |
| Reflected XSS / open-redirect probes | working (payload injection) | working (benign markers, common params) | 🔁 Parity |
| Verbose error / stack exposure | (part of runtime) | working (`_STACK_MARKERS`) | 🔁 Parity |
| Fuzzing engine (multi-strategy) | stub (design-only) | — | 🗑️ Dropped-but-was-stub |
| `--pentest` aggressive mode | working | — (replaced by non-invasive probes) | ❌ Dropped |

### AI / LLM

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| LLM vuln explanation (Claude/OpenAI) | working (`llm_analyzer.py`) | working (Tier 3 remote) | 🔁 Parity |
| Offline/built-in explanations | — (LLM required) | working (Tier 1, every finding) | ➕ New in V2 |
| Local-model explanations (Ollama) | — | working (Tier 2, default, free, private) | ➕ New in V2 |
| Privacy controls (redaction, `--no-external`) | — | working (redaction on by default) | ➕ New in V2 |
| LLM false-positive filtering | working | folded into confidence/ignore logic | 🔁 Parity |
| Behavioral analyzer (anomaly/APT) | crash-on-import (unguarded numpy) | — | 🗑️ Dropped-but-was-crash |
| Threat intelligence engine (IOC/feeds) | partial (logic incomplete) | — | 🗑️ Dropped-but-was-partial |
| Intelligence orchestrator | crash-on-import | — | 🗑️ Dropped-but-was-crash |

### Reports & Output

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| Terminal report (Rich) | working | working (severity chips, taint flow) | 🔁 Parity |
| HTML report | working (charts.js) | working (self-contained, dark theme) | 🔁 Parity |
| JSON report | working | working (richer schema + fingerprints) | ✅ Improved |
| SARIF 2.1.0 (GitHub) | working | working (rules, CWE/OWASP tags) | 🔁 Parity |
| CSV / XML formats | working (choices listed) | — | ❌ Dropped (minor) |
| `--brief` terse output | — | working | ➕ New in V2 |
| Executive summary report | partial | — | 🗑️ Dropped-but-was-partial |
| SBOM (CycloneDX/SPDX/SWID) | broken (missing `Set` import) | — | 🗑️ Dropped-but-was-broken |

### Dependencies & Data

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| Local CVE database | working (cve_database.json) | working (shipped advisory seed) | 🔁 Parity |
| Vuln data updater | partial (external feeds) | working (`update` → OSV.dev cache) | ✅ Improved |
| Framework security rules data | working (yaml/json) | working (121 rules + 127 patterns YAML) | ✅ Improved |
| MITRE ATT&CK framework data | working | — | ❌ Dropped |
| Dependency graph + risk scoring | working (`dep_graph.py`) | semver range matching (no full graph) | 🔁 Parity (narrowed) |

### Infrastructure

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| Circuit breaker | working | — (simpler per-detector error capture) | 🗑️/❌ (internal) |
| Rate limiter (token bucket/sliding) | working | — | ❌ Dropped (internal) |
| Retry handler (backoff) | working | — | ❌ Dropped (internal) |
| Caching system | working | — (no user-facing cache) | ❌ Dropped (internal) |
| Performance monitoring | working | — | ❌ Dropped (internal) |
| Plugin system (auto-discovery) | working | — | ❌ Dropped |
| Graceful degradation (missing extras) | (implicit) | working (tree-sitter/httpx optional, no crash) | ✅ Improved |
| Framework auto-detection | (via `--framework`) | working (Next/React/Vite/Vue/Svelte/Node) | ✅ Improved |
| Config file (`.njordscan.yml`) | — | working (team-shared, CLI overrides) | ➕ New in V2 |
| Baseline management | — | working | ➕ New in V2 |
| Git-diff / PR scanning | — | working | ➕ New in V2 |
| Autofix engine (`--fix`/`--dry-run`) | — | working (provably-safe, additive) | ➕ New in V2 |
| MCP server (JSON-RPC stdio, 3 tools) | — | working | ➕ New in V2 |

### Dev / CI / Docs

| Feature | V1 (status) | V2 (status) | Verdict |
|---|---|---|---|
| CI/CD integration | partial (flags only, minimal orchestration) | working (`action.yml` + pre-commit hook) | ✅ Improved |
| GitHub Actions composite action | — (no shipped asset) | working (`action.yml`) | ➕ New in V2 |
| Pre-commit hook | — | working (`.pre-commit-hooks.yaml`) | ➕ New in V2 |
| Optional extras `[ai]`/`[dynamic]`/`[dev]` | (monolithic deps) | working (lazy imports) | ✅ Improved |
| Test suite | (not catalogued) | working (60 pytest tests) | ➕ New in V2 |
| Documentation set | (not catalogued) | working (9 guides + 126KB RULES.md) | ➕ New in V2 |
| Inline `njordscan-ignore`/`nosec` | — | working | ➕ New in V2 |

---

## 3. Genuinely Dropped (worth knowing)

These were **real, at-least-partly-working V1 features** that V2 does not (yet) have. DAST is **not** here — it existed in both and is actually better in V2.

1. **SBOM generation** — V1 had CycloneDX/SPDX/SWID output, but it was **broken** (`Set` not imported). The intent was real; the feature is gone. Likely the most-missed capability for compliance users.
2. **Results history: `results --list-scans`, compare, trends** — the `--list-scans` reader genuinely worked (read from cache). V2 has no scan-history store (baseline/diff partially replace the use case but aren't a history browser).
3. **Plugin system + `plugins` command** — `PluginManager` with discovery/load worked; CLI `list/browse/install/create` were partly functional. No plugin extensibility in V2.
4. **`learn` tutorials** — `--topic` content genuinely worked. No learning/education command in V2 (though every finding now carries why/fix/secure_example).
5. **`legal` command** — fully working disclaimer/terms accept/clear flow. Gone.
6. **`cache stats` / `cache clear`** — working cache-inspection commands. V2 has no user-facing cache.
7. **MITRE ATT&CK data + mapping** — shipped and working in V1. Not in V2.
8. **`--pentest` aggressive mode** — working in V1; V2 deliberately ships only non-invasive DAST probes (a safety choice, but it *is* a removed capability).
9. **`--framework` force-detection flag** — V2 auto-detects but offers no manual override.
10. **`--timeout`, `--threads`, CSV/XML report formats** — small but real working V1 options with no V2 equivalent.
11. **Auto-updating CVE feed (`VulnerabilityDataManager`)** — V1's multi-source feed was *partial*; V2 replaces it with a simpler, working OSV.dev `update`. Net: the broad multi-feed ambition is dropped, the working subset is improved.

(Internal infra — circuit breaker, rate limiter, retry handler, caching, perf monitor — were real and working in V1 but are plumbing, not user features; V2 dropped them for a simpler architecture.)

---

## 4. Dropped on Purpose (not a loss)

These V1 items were **stub, broken, or crash-on-import** — removing them shed size without shedding real capability:

- **Behavioral analyzer** — `crash-on-import` (unconditional `import numpy` not in `install_requires`).
- **Intelligence orchestrator** — `crash-on-import` (pulled in the broken behavioral analyzer; only survived via try/except fallback).
- **Threat intelligence engine** — `partial`: rich data structures, but feed integration / IOC correlation incomplete.
- **Fuzzing engine** — `stub`: enums and class shells, "design-only," no real fuzzing logic.
- **SBOM generator** — `broken`: `NameError` on `Set` at runtime (line 584).
- **`setup` wizard** — `stub`: prints "not yet available."
- **`community` command** — `stub`: prints "not yet available."
- **`fix` command (legacy)** — `stub`: prints "not yet available" (V2's `scan --fix` is the real version).
- **`--interactive`, `--quality-gate`, `--show-progress`, `--executive-summary`, `--trend-analysis`, `--theme`, `--memory-limit`, `--threat-intel`, `--community-rules`, `--behavioral-analysis`** — all `partial`: accepted by Click but not wired into working behavior (flags that looked like features).
- **Next.js Advanced Plugin** (`plugins/frameworks/nextjs_advanced/`) — `stub`: structure only.

---

## 5. Bottom-Line Counts

**V1 catalog: 87 items.**
- Working: **52**
- Partial: **24**
- Stub: **7**
- Broken: **1** (SBOM)
- Crash-on-import: **2** (behavioral analyzer, intelligence orchestrator)
- → **52 genuinely working / 35 stub-partial-broken-or-crashing** (~40% of V1's surface area was not real).

**V2 catalog: 53 items — all 53 working.**
- New-in-V2 capabilities: **~18** (MCP server + 3 tools, autofix/dry-run, baseline + update-baseline, git-diff PR mode, three-tier AI with Ollama + offline + privacy controls, `.njordscan.yml` config, `init`, git-hygiene detector, data-driven pattern engine, `action.yml`, pre-commit hook, optional extras, 60-test suite, docs set, `--brief`, `--ignore`, inline ignore comments).

**Net:** V2 ships ~53 working features vs V1's 52 *actually-working* features (out of 87 advertised). V2 has roughly the same real footprint as V1 with a markedly higher working-rate (~100% vs ~60%), trades away SBOM / plugins / results-history / learn / legal / MITRE / threat-intel ambitions, and adds a modern CI + AI-assistant + PR-centric workflow that V1 never actually delivered.

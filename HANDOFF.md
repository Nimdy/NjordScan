# NjordScan V2 — Handoff / Kickoff Prompt

> Paste this to a fresh Claude Code session opened on this folder. It is the project
> bible: mission, architecture, conventions, current state, and what to do next.

---

## 1. Mission

NjordScan is a security scanner for **Next.js / React / Vite** apps, built for developers who
ship fast and **are not security experts** ("vibe coders"). The defining quality: **every
finding teaches** — it states *why it matters* and *exactly how to fix it*, in plain English,
with a copy-paste secure example.

This is **V2**, a clean-room rebuild. It lives at the **root of this repo on the `v2` branch**;
the original V1 is on the **`main` branch** of the same repo (reference only — do not import its
code; browse it with `git show main:<path>` or `git checkout main`). V1 was ~60k LOC, crashed on
install, and had major false negatives; V2 is ~5.8k LOC, installs clean, and is provably
trustworthy. The full V1 review is in the project memory (`njordscan-v1-review-findings`) and the
rebuild rationale in `njordscan-v2-rebuild`. When V2 is ready to become the product, open a
`v2 → main` PR.

**North-star priorities (in order):** (1) never produce false negatives on the things this
audience can't catch themselves; (2) install and run flawlessly with zero config; (3) every
finding is educational and actionable; (4) the tool itself is secure and private; (5) be honest
(no overclaiming). Aspiration: the best-in-class scanner for this stack.

## 2. The non-negotiable principles (do not violate)

- **Zero false positives on clean code.** A clean app MUST produce 0 findings. This is the trust
  moat — `tests/fixtures/clean-app` and the pattern-library tests enforce it. If you add a rule,
  add a vulnerable fixture AND a safe fixture, and confirm the safe one stays silent.
- **Every rule is educational.** Every `rule_id` MUST have a knowledge entry with a non-empty
  `why` and `fix`. Detectors emit only `rule_id` + location; the knowledge base supplies the rest.
  `tests/test_pattern_library.py` fails if a pattern has no knowledge entry (no "orphans").
- **Never crash on user code.** `Detector.scan()` must never raise — wrap parsing/IO; return
  partial results. Missing optional deps (e.g. tree-sitter) degrade gracefully, never crash import.
- **Installs clean everywhere.** Core deps are pure-python / prebuilt wheels only. NO numpy/pandas/
  heavy/system libs in `[project.dependencies]`. Optional stuff goes in extras (`[ai]`).
- **Private by default.** Nothing leaves the machine unless the user passes an AI flag. Remote AI
  redacts secrets from code first and prints a consent notice.
- **Autofix is sacred.** `--fix` only applies *provably-safe, additive* changes. A wrong auto-edit
  destroys trust forever. When in doubt, leave it as a documented manual fix.
- **TypeScript-grade typing/voice.** Match the existing code style and the beginner-friendly,
  consequence-first explanation voice in `njordscan/knowledge/rules.py`.

## 3. Layout & how to run

```
njordscan/
  cli.py                 # click CLI: scan, explain, init, update, doctor, version
  core/
    severity.py finding.py config.py project.py orchestrator.py
    baseline.py configfile.py paths.py
  detectors/             # secrets, supply_chain, dependencies, static_analysis,
    base.py __init__.py  #   taint, configs, pattern_engine, git_hygiene  (registry in __init__)
  knowledge/             # rules.py (core rules) + loader.py (YAML rules) + __init__ (enrich + registry)
  explain/               # 3-tier AI: engine.py providers.py redact.py  (offline always; ollama/claude/openai opt-in)
  report/                # terminal.py json_report.py sarif.py html.py
  fix/                   # safe autofixers
  update.py              # OSV.dev advisory refresh -> ~/.njordscan/advisories.json
  data/
    rules/*.yaml         # knowledge entries (id/title/severity/cwe/owasp/why/fix/secure_example/refs)
    patterns/*.yaml      # detection patterns (rule_id + regex + lang/framework/path/requires/exclude filters)
    advisories/known_vulns.json   # shipped CVE seed (merged with the OSV user cache)
tests/
  conftest.py            # sets NJORDSCAN_HOME to an empty dir so tests ignore the user OSV cache
  fixtures/{vulnerable-app,clean-app,rule-cases/<category>/...}
  test_*.py              # 42 tests
```

```bash
# the venv already exists at .venv
source .venv/bin/activate          # or use .venv/bin/<tool> directly
pip install -e '.[dev]'            # dev tools (pytest, ruff, mypy)
pytest -q                          # 42 tests, ~1.5s
njordscan scan tests/fixtures/vulnerable-app     # ~41 findings, all explained
njordscan scan tests/fixtures/clean-app          # must be ~0 (dep CVEs only, from live cache)
njordscan doctor                                 # health: detectors, rules, advisories, AI
```

## 4. How to add a rule (the common task)

1. Add a knowledge entry to the right `njordscan/data/rules/<category>.yaml`
   (`id`, `title`, `severity`, `cwe`, `owasp`, `why`, `fix`, `secure_example`, `references`).
2. Add one or more detection patterns to `njordscan/data/patterns/<category>.yaml` referencing that
   `rule_id` (`pattern` regex + precision filters: `languages`, `frameworks`, `paths`,
   `requires_line`, `requires_file`, `exclude_line`, `multiline`). Lines with `// njordscan-ignore`
   are auto-skipped.
3. Add a vulnerable example AND a safe variant under `tests/fixtures/rule-cases/<category>/`.
4. Verify: `njordscan scan tests/fixtures/rule-cases/<category> --only patterns` fires on the
   vuln, stays silent on the safe one; `--only patterns` on `clean-app` is still 0.
   For data-flow sinks/sources, edit `detectors/taint.py` instead (tree-sitter AST).

## 5. Current state (done)

- 8 detectors; **100 knowledge rules / 107 patterns** across react/dom, nextjs, vite, crypto-jwt,
  injection, cookies-auth, cors-headers-csrf, hardening, git-hygiene. 0 orphans, 0 clean-app FPs.
- Headline taint: cross-function + JSX `dangerouslySetInnerHTML` (the V1 misses) — verified.
- Secrets in code + `.env*`; dependencies vs CVE DB (OSV-refreshable); supply-chain; git-hygiene.
- Reports: terminal (rich, educational), JSON, SARIF 2.1.0 (with taint code flows), HTML.
- `--fix` (+`--dry-run`), `--baseline`/`--update-baseline`, `.njordscan.yml`+`init`, `update`
  (OSV), `doctor`, 3-tier hybrid explain, `// njordscan-ignore`, comma or repeated `--only/--skip`.
- CI: `action.yml` (composite), `.pre-commit-hooks.yaml`, `.github/workflows/ci.yml`.
- 42 passing tests; clean PyPI-style wheel install verified (12 deps, no numpy).
- Exit codes: 0 clean / 1 met `--fail-on` / 2 scan error.

## 6. Known limitations / good next steps (roughly prioritized)

1. **Publish to PyPI** so `pip install njordscan` is real (update URLs/author in `pyproject.toml`).
2. **More autofixers** — security headers block for `next.config`, cookie flag additions, CSP
   tightening (each must stay provably safe; prefer additive).
3. **Grow the rule library** against real-world repos; watch precision (every new rule needs a safe
   fixture). Candidate gaps: GraphQL auth, RSC data exposure, `Server Action` authorization,
   websocket origin, rate-limiting heuristics.
4. **Taint depth**: it currently catches cross-function + direct sinks; `static` covers the rest.
   Consider unifying overlap and adding arrow/method coverage to reduce reliance on regex `static`.
5. **`njordscan update` UX**: cache OSV results with a timestamp; add `--offline`; consider OSV
   batch API for speed.
6. **Severity/confidence calibration** pass across the 100 rules using real projects.
7. **mypy strict + ruff clean** in CI; raise coverage on `cli.py`, `update.py`, `explain/`.
8. Optional: `watch` mode, custom user rule dirs, SBOM, dependency-graph transitive risk.

## 7. Guardrails for whatever you change

- Run `pytest -q` after every change; keep it green. Add a test for new behavior.
- Re-verify `njordscan scan tests/fixtures/clean-app --only patterns` == 0 after touching rules.
- Don't add a dependency to core just for one feature — use an extra and lazy-import.
- Keep the CLI non-interactive and exit codes stable (CI depends on them).
- Update this file and the project memory when the architecture or priorities shift.

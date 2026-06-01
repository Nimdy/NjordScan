# Contributing to NjordScan

Thanks for helping make web security approachable! NjordScan is built for developers who aren't
security experts, so the bar for every change is: **does it stay accurate, trustworthy, and
self-explaining?**

## Principles (please don't break these)

- **Zero false positives on clean code.** A clean app must produce 0 findings — that's the trust
  moat. Every new rule needs a vulnerable fixture *and* a safe fixture that stays silent.
- **Every rule teaches.** Each rule has a plain-English `why` and `fix` (and ideally a secure
  example). No jargon-only findings.
- **Never crash on user code.** Detectors catch their own errors and return partial results.
- **Installs clean.** No heavy/system dependencies in the core; optional features go in extras.
- **Private by default.** Nothing leaves the machine unless the user passes an AI/`--url` flag.

## Dev setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,dynamic,ai]'
pytest -q          # 55 tests, ~3s
ruff check njordscan
```

## Add a rule (the most common contribution)

Most rules are pure data — no Python needed:

1. Add the explanation to the right `njordscan/data/rules/<category>.yaml`
   (`id`, `title`, `severity`, `cwe`, `owasp`, `why`, `fix`, `secure_example`, `references`).
2. Add one or more detection patterns to `njordscan/data/patterns/<category>.yaml` referencing that
   `id` (regex + precision filters: `languages`, `frameworks`, `paths`, `requires_line`,
   `requires_file`, `exclude_line`, `multiline`). See the pattern engine's docstring for the schema.
3. Add a `*.vuln.*` and a `*.safe.*` fixture under `tests/fixtures/rule-cases/<category>/`.
4. Verify precision:
   ```bash
   njordscan scan tests/fixtures/rule-cases/<category> --only patterns   # fires on vuln, not on safe
   njordscan scan tests/fixtures/clean-app --only patterns                # still 0
   ```
5. Regenerate the catalog: `python scripts/gen_docs.py` (updates `docs/RULES.md`).

For data-flow rules (a source reaching a sink), edit the tree-sitter taint detector
`njordscan/detectors/taint.py` instead of using a regex pattern.

## Project map

The module layout, in short:

- `core/` — severity, the `Finding` model, config, project model, orchestrator
- `detectors/` — secrets, supply-chain, dependencies, static, taint, configs, patterns,
  git-hygiene, runtime (DAST)
- `knowledge/` — the rule registry + YAML loader + `enrich()`
- `report/` — terminal / json / sarif / html
- `explain/` — the opt-in AI explanation tiers
- `fix/` — safe autofixers
- `mcp_server.py` — the MCP server

## Before you open a PR

- `pytest -q` is green and you added a test for new behavior.
- `ruff check njordscan` passes.
- `njordscan scan tests/fixtures/clean-app` still reports 0 findings.
- You did **not** add a contiguous real-format secret literal to any fixture (build it at runtime
  if a key shape is needed — GitHub push protection blocks committed provider keys).

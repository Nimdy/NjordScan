<!--
Thanks for helping make web security approachable! Keep this PR focused.
See CONTRIBUTING.md for dev setup, the project map, and how to add a rule.
-->

## What & why

<!-- What does this change do, and why does it matter for the kind of dev who isn't a security expert? -->

## Type of change

- [ ] New rule (or pattern improvement)
- [ ] Bug fix
- [ ] New feature
- [ ] Docs only
- [ ] Refactor / internal

## Checklist

- [ ] Ran `pytest -q` and it's green
- [ ] Ran `ruff check njordscan` and it passes
- [ ] Added or updated a test for this change
- [ ] `njordscan scan tests/fixtures/clean-app` still reports **0** findings
- [ ] Did **not** commit a real-format secret literal to any fixture (build key shapes at runtime)
- [ ] Updated the docs / CHANGELOG if behavior or output changed

## For a new rule

<!-- Skip this section if your change isn't a rule. -->

- [ ] Added the explanation (`why` + `fix`) to `njordscan/data/rules/<category>.yaml`
- [ ] Added a `*.vuln.*` **and** a `*.safe.*` fixture under `tests/fixtures/rule-cases/<category>/`
- [ ] Verified it fires on the `.vuln` fixture and stays silent on the `.safe` one
- [ ] Regenerated the catalog with `python scripts/gen_docs.py` (updates `docs/RULES.md`)

## Notes for reviewers

<!-- Anything you're unsure about, trade-offs you made, or follow-ups you're leaving for later. -->

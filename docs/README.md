# NjordScan documentation

Security scanning for Next.js, React & Vite — **explained in plain English**, for developers who
aren't security experts.

New here? Start with **[Getting started](getting-started.md)**, then come back for the rest.

## Guides

| Guide | What it covers |
|-------|----------------|
| [Getting started](getting-started.md) | Install, your first scan, and how to read the results |
| [Configuration](configuration.md) | `.njordscan.yml`, ignoring findings, choosing detectors |
| [CI/CD & PRs](ci-cd.md) | GitHub Actions, pre-commit, `--fail-on`, `--diff`, baselines, SARIF |
| [Dynamic scanning (DAST)](dynamic-scanning.md) | Scanning a live app with `--url` (and how it stays safe) |
| [AI features](ai-features.md) | AI-app security rules + opt-in AI explanations (offline / Ollama / API) |
| [AI coding assistants (MCP)](ai-assistant-mcp.md) | Let Claude Code / Cursor scan inline while you build |
| [Troubleshooting & FAQ](troubleshooting.md) | Common questions and fixes |
| [**Rules catalog**](RULES.md) | Every rule NjordScan detects, with why + fix (auto-generated) |

## Reference

- **[Rules catalog](RULES.md)** — all 120+ checks. Or run `njordscan explain <rule-id>` in your terminal.
- **[V1 vs V2](V1-vs-V2.md)** — complete feature comparison of the old and new versions.
- **[Changelog](../CHANGELOG.md)** — what changed.
- **[Contributing](../CONTRIBUTING.md)** — add a rule, run the tests.

## The one-minute version

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install njordscan
njordscan scan .                    # scan; every finding tells you why + how to fix
njordscan scan . --fail-on high     # for CI: exit 1 on High/Critical
njordscan explain <rule-id>         # deep-dive any finding
njordscan doctor                    # check what's installed
```

Nothing leaves your machine unless you explicitly pass an AI flag or `--url`.

# CI/CD & pull-request workflow

This guide shows how to run NjordScan automatically — on every push, on every pull request, and
even before a commit ever leaves your laptop. The goal: catch the security issues that actually
bite web apps (exposed secrets, XSS, risky config) *before* they reach `main`, without slowing
your team down or drowning anyone in noise.

You don't need to be a security expert to set this up. Every snippet below is copy-paste ready,
and every command has been run against a real repo to confirm it does what it says.

New to NjordScan? Start with the [README](../README.md). Want the full list of what it checks?
See the [rules catalog](RULES.md).

---

## The one idea that makes CI work: exit codes

A CI job decides "pass" or "fail" by looking at the **exit code** of the command it ran. `0`
means success; anything else means failure. NjordScan is built around this:

| Exit code | What it means | Typical CI result |
|-----------|---------------|-------------------|
| `0` | Clean — no findings, **or** findings exist but all are *below* your `--fail-on` threshold | ✅ job passes |
| `1` | At least one finding is **at or above** your `--fail-on` severity | ❌ job fails |
| `2` | The scan itself couldn't run (bad path, broken config, etc.) | ❌ job fails (and worth investigating) |

The key flag is **`--fail-on`**. It sets the severity bar that breaks the build:

```bash
njordscan scan . --fail-on high
```

That says: "fail the job if there's anything **High or Critical**; let Medium/Low through." The
choices are `info`, `low`, `medium`, `high`, `critical`. Pick the lowest severity you're willing
to *block a merge* over. `high` is a sensible starting point — strict enough to stop real
problems, loose enough that you won't get blocked on day one.

A quick demonstration on a repo with three High-severity findings (an exposed token, a database
URL with a password, and an XSS sink):

```bash
$ njordscan scan . --fail-on high --quiet
NjordScan: 3 issue(s) — 0 critical, 3 high, 0 medium, 0 low.
$ echo $?
1                      # ← the 3 High findings tripped --fail-on high

$ njordscan scan . --fail-on critical --quiet
NjordScan: 3 issue(s) — 0 critical, 3 high, 0 medium, 0 low.
$ echo $?
0                      # ← same 3 High findings, but none are Critical, so the job passes
```

> **`--fail-on` vs `--min-severity`.** `--fail-on` controls the *exit code* (does the build
> break?). `--min-severity` controls what's *shown* in the report (it hides quieter findings).
> They're independent — you can show everything but only fail on High, or vice versa. More on
> tuning these in the [README](../README.md).

`--quiet` (used above) prints just the one-line summary, which keeps CI logs tidy. Drop it when
you want the full educational report inline.

---

## Option A: the GitHub Action (recommended)

NjordScan ships a reusable **composite Action**, so a working PR scan is about ten lines. It
installs NjordScan, runs the scan, and produces a **SARIF** report — the format GitHub
understands natively, so findings show up inline on the **Security → Code scanning** tab and as
annotations right on the pull-request diff.

Create `.github/workflows/security.yml`:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

# Lets the workflow upload SARIF to GitHub code scanning.
permissions:
  contents: read
  security-events: write

jobs:
  njordscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: NjordScan security scan
        uses: Nimdy/NjordScan@v2.0.0b1
        with:
          path: "."
          fail-on: high
          format: sarif
          output: njordscan.sarif

      # Upload the SARIF even if the scan failed, so findings still
      # appear on the Security tab and on the PR diff.
      - name: Upload SARIF to GitHub code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: njordscan.sarif
```

### The Action's inputs

These are the **only** inputs the Action accepts (verified against
[`action.yml`](../action.yml)):

| Input | Default | What it does |
|-------|---------|--------------|
| `path` | `.` | Directory to scan. |
| `fail-on` | `high` | Fail the job at or above this severity (`critical`/`high`/`medium`/`low`). **Leave empty to never fail the job** — handy if you only want findings on the Security tab without blocking merges. |
| `format` | `sarif` | Report format: `sarif`, `json`, or `html`. Keep `sarif` for the code-scanning upload to work. |
| `output` | `njordscan.sarif` | Where the report is written. |

Under the hood the Action just runs `pip install njordscan` and then
`njordscan scan <path> --format <format> -o <output> --fail-on <fail-on>` — nothing magic, so
anything you can do on the CLI you can reproduce locally.

### Why `if: always()` on the upload

If a High finding makes the scan step exit `1`, the job is already "failing." Without
`if: always()`, GitHub would skip the upload step and you'd lose the SARIF — meaning the
findings that *caused* the failure never show up on the Security tab. `if: always()` runs the
upload regardless, so you get both the red ❌ *and* the detailed annotations explaining why.

### Tips

- **PR-only annotations.** With the `pull_request` trigger above, GitHub automatically diffs the
  SARIF and shows new findings as inline comments on the changed lines. To scan *only* the lines
  a PR touched (and skip pre-existing issues entirely), see [`--diff`](#pr-only-findings-with---diff)
  below.
- **Pinning.** Pin to a release tag for reproducible CI — e.g. `Nimdy/NjordScan@v2.0.0b1` — or to a
  commit SHA for the strongest guarantee. Avoid pinning to `@main` (it moves).

---

## Option B: a manual pip-install workflow

Prefer not to depend on the composite Action — maybe you want to add caching, run extra steps,
or scan in a custom way? Install NjordScan yourself. This is also the pattern to adapt for
**GitLab CI, CircleCI, Jenkins**, or any other runner — the commands are identical; only the YAML
wrapper changes.

`.github/workflows/security.yml`:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  njordscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install NjordScan
        run: pip install njordscan          # tiny core, no build tools needed

      - name: Run NjordScan
        run: njordscan scan . --format sarif -o njordscan.sarif --fail-on high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: njordscan.sarif
```

A couple of things worth knowing:

- **Speed.** For fast feedback on every push you can add `--mode quick`, which skips the two
  heaviest detectors (`taint` and `dependencies`). Keep a full `standard` scan on `main` or
  nightly so nothing slips through. The default mode is `standard`.

  ```bash
  njordscan scan . --mode quick --fail-on high
  ```

- **Generic CI (no SARIF upload).** On a runner without GitHub code scanning, just rely on the
  exit code and (optionally) save a human-readable report as a build artifact:

  ```bash
  njordscan scan . --fail-on high --format html -o njordscan-report.html
  ```

  Exit `1` fails the pipeline; the HTML is a shareable report you can attach to the build.

---

## Catch issues *before* commit: the pre-commit hook

The cheapest place to catch a leaked secret is on the developer's own machine — before it's ever
committed. NjordScan ships a [pre-commit](https://pre-commit.com/) hook for exactly this.

In your repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Nimdy/NjordScan
    rev: v2.0.0b1
    hooks:
      - id: njordscan
```

Then install it once:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files     # optional: scan everything right now
```

From now on, `git commit` runs NjordScan first. The shipped hook (see
[`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml)) runs:

```text
njordscan scan --fail-on high --quiet
```

so a commit that introduces a High/Critical issue is **blocked** (exit `1`) with a one-line
summary. To change the strictness, override the args in your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Nimdy/NjordScan
    rev: v2.0.0b1
    hooks:
      - id: njordscan
        args: ["--fail-on", "critical", "--quiet"]   # only block on Critical
```

> The hook scans the whole project (`pass_filenames: false`, `always_run: true`), not just the
> staged files — so it catches issues anywhere, not only in what you happened to touch. It's a
> safety net, not a replacement for the CI scan; keep both.

If a hook ever blocks a commit on something you've reviewed and accept, you can silence that one
line by adding a comment containing `njordscan-ignore` (or `nosec`) to it — see the
[README](../README.md) for how per-line ignores work.

---

## PR-only findings with `--diff`

Adopting a scanner on an existing codebase has a classic problem: the first scan lights up with
dozens of pre-existing issues that have nothing to do with the change in front of you. `--diff`
fixes that by reporting only issues on **lines changed versus a git ref** — perfect for pull
requests, where you only want to hold contributors accountable for what *they* added.

```bash
njordscan scan . --diff origin/main --fail-on high
```

That compares the working tree against `origin/main` and only surfaces (and only fails on)
findings on the added/changed lines. Bare `--diff` (no ref) compares against `HEAD`.

Verified behavior on a repo where the new commits added three High findings:

```bash
# Diffing against the first commit — the new findings are on changed lines, so they show:
$ njordscan scan . --diff <first-commit-sha> --fail-on high --quiet
NjordScan: 3 issue(s) — 0 critical, 3 high, 0 medium, 0 low.
$ echo $?
1

# A later commit that only added a clean line, diffed against HEAD — nothing new, build passes:
$ njordscan scan . --diff --fail-on high --quiet
NjordScan: 0 issue(s) — 0 critical, 0 high, 0 medium, 0 low.
$ echo $?
0
```

In a GitHub Actions PR job, make sure the base branch is available before you diff. The default
`actions/checkout@v4` does a shallow clone, so fetch a bit more history first:

```yaml
jobs:
  njordscan-pr:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0           # fetch full history so --diff can compare branches

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install njordscan

      - name: Scan only what this PR changed
        run: njordscan scan . --diff "origin/${{ github.base_ref }}" --fail-on high
```

`github.base_ref` is the branch the PR targets (usually `main`), so this fails the PR only if the
**diff itself** introduces a High/Critical issue. Existing debt is left for another day.

---

## Adopt on a messy repo with `--baseline`

`--diff` is ideal for PRs, but sometimes you want CI to enforce "**no new issues**" across the
*whole* project — push runs included — while you pay down existing findings gradually. That's what
a **baseline** is for. You take a one-time snapshot of today's findings; from then on NjordScan
hides those known issues and only fails on **new** ones.

**Step 1 — record the baseline** (run once, commit the file):

```bash
njordscan scan . --baseline .njordscan-baseline.json --update-baseline
```

```text
✓ Baseline updated: 3 finding(s) recorded in .njordscan-baseline.json
```

`--update-baseline` writes the snapshot and exits `0` — it never fails the build, even if there
are findings, so it's safe to run anywhere. Commit `.njordscan-baseline.json` to your repo.

**Step 2 — scan against it** in CI:

```bash
njordscan scan . --baseline .njordscan-baseline.json --fail-on high
```

Known findings are suppressed, so a repo that's unchanged since the snapshot reports clean and
passes:

```bash
$ njordscan scan . --baseline .njordscan-baseline.json --fail-on high --quiet
NjordScan: 0 issue(s) — 0 critical, 0 high, 0 medium, 0 low.
$ echo $?
0
```

But introduce a *new* secret and only that one shows up — and breaks the build:

```bash
$ njordscan scan . --baseline .njordscan-baseline.json --fail-on high --quiet
NjordScan: 1 issue(s) — 0 critical, 1 high, 0 medium, 0 low.   # ← only the new one
$ echo $?
1
```

As you fix old issues, re-run `--update-baseline` to shrink the snapshot, until one day you can
delete the baseline file entirely and enforce a totally clean repo.

You can also set the baseline path in your `.njordscan.yml` config (`baseline: .njordscan-baseline.json`)
so you don't have to repeat the flag — run `njordscan init` to generate a starter config, and see
the [README](../README.md) for all the config keys.

> **`--diff` or `--baseline`?** Use **`--diff origin/main`** to scan only a PR's changed lines —
> simplest, no extra file to maintain. Use **`--baseline`** when you want full-project coverage
> on every run while ignoring pre-existing debt, or when you're not always running inside a git
> diff. Many teams use `--diff` on PRs and a baseline'd full scan on `main`.

---

## A complete, copy-paste workflow

Putting it together — quick PR-only feedback plus a full baselined scan on `main`, with SARIF
uploaded both ways:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install njordscan

      # On PRs: fail only on issues this PR introduces.
      - name: PR scan (changed lines only)
        if: github.event_name == 'pull_request'
        run: njordscan scan . --diff "origin/${{ github.base_ref }}" --fail-on high --format sarif -o njordscan.sarif

      # On main: full scan, ignoring pre-existing baselined debt.
      - name: Full scan (main)
        if: github.event_name == 'push'
        run: njordscan scan . --baseline .njordscan-baseline.json --fail-on high --format sarif -o njordscan.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: njordscan.sarif
```

---

## Where to go next

- **[README](../README.md)** — install, full flag reference, per-line ignores, and config file
  keys.
- **[Rules catalog](RULES.md)** — every rule NjordScan checks, with plain-English explanations.
- **[AI assistants (MCP)](ai-assistant-mcp.md)** — let your AI coding assistant scan as you build.

Run `njordscan doctor` any time to confirm what's installed and working in your CI image
(detectors, rule counts, advisory freshness).

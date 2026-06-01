# Configuration

NjordScan works with zero configuration — `njordscan scan` just runs. But once
you've used it for a bit, you'll probably want to make a few decisions stick: which
findings are worth failing a build over, which folders to skip, which one rule you've
already reviewed and don't want to hear about again. You write those decisions down
once, commit them, and everyone on your team (plus CI) runs the exact same scan.

There are two places settings can live:

1. **A config file** — `.njordscan.yml`, committed to your repo. This is the shared,
   permanent home for your team's choices.
2. **Command-line flags** — like `--min-severity high` or `--skip dependencies`. These
   are for one-off runs, and they **override** the file when the two disagree.

New to NjordScan? Start with the **[Getting started guide](getting-started.md)** first,
then come back here. The full list of every rule NjordScan checks lives in the
**[Rules catalog](RULES.md)**.

---

## Quick start: `njordscan init`

You don't have to write the config file by hand. Run `init` and NjordScan drops a
starter `.njordscan.yml` into the current directory with every key already commented:

```bash
njordscan init
```

```
✓ Wrote .njordscan.yml
Edit it to fit your project, then run njordscan scan .
```

A few details worth knowing:

- It writes into the **current** directory by default. To target somewhere else, pass a
  path: `njordscan init path/to/project`.
- If a `.njordscan.yml` is already there, NjordScan refuses to clobber it:

  ```
  .njordscan.yml already exists. Use --force to overwrite.
  ```

  Add `--force` if you really do want to start over: `njordscan init --force`.

Open the file, uncomment the keys you care about, and you're done. The rest of this
page explains what each key does.

---

## The full `.njordscan.yml`, every key explained

Here is a config that uses **every** supported key, each one commented. You won't want
all of these at once — copy the lines you need. Every key is optional.

```yaml
# .njordscan.yml — committed to your repo so the whole team scans the same way.
# All keys are optional. Command-line flags override anything you set here.

# ── What you see ──────────────────────────────────────────────────────────────
# Hide findings quieter than this. Anything below the level is dropped from the
# report entirely. Levels, lowest to highest: info, low, medium, high, critical.
min_severity: low

# ── What fails the build (for CI) ─────────────────────────────────────────────
# If any finding is at or ABOVE this level, `njordscan scan` exits with code 1.
# Leave it out and the scan always exits 0 (it just reports). See "Exit codes" below.
fail_on: high

# ── Files and folders to never scan ───────────────────────────────────────────
# Glob patterns, added on top of the sensible built-in defaults (node_modules, etc).
# Use these for generated code, vendored libraries, or legacy areas you can't fix yet.
ignore:
  - "**/legacy/**"
  - "**/*.min.js"
  - "src/generated/**"

# ── Detectors to turn off completely ──────────────────────────────────────────
# A "detector" is one family of checks. Valid ids: secrets, supply-chain,
# dependencies, static, taint, configs, patterns, git-hygiene, runtime.
skip_detectors:
  - runtime

# ── Detectors to run EXCLUSIVELY ──────────────────────────────────────────────
# If set, ONLY these detectors run and everything else is off. Leave it empty ([])
# to run everything. (Don't set both only_detectors and skip_detectors — only_detectors
# wins.)
only_detectors: []

# ── Specific rules you've reviewed and want silenced everywhere ────────────────
# These are rule ids (from `njordscan explain` or the Rules catalog), not detector
# ids. The finding disappears from every file. Use this when you've looked at a rule,
# decided it's a false positive for your project, and don't want to see it again.
disable_rules:
  - react.unsafe-target-blank

# ── Change how serious a rule is ──────────────────────────────────────────────
# Map a rule id to a new severity (info|low|medium|high|critical). Handy to promote
# something to "critical" so it trips your fail_on gate, or to demote a noisy rule.
severity:
  xss.inner-html: critical
  crypto.weak-hash: high

# ── Baseline: only fail on NEW problems ───────────────────────────────────────
# Point at a baseline file. NjordScan hides findings already recorded there and only
# reports (and fails on) NEW ones — perfect for adopting it into an old project.
# Create/refresh the file with:  njordscan scan --update-baseline
baseline: .njordscan-baseline.json

# ── Optional AI explanations ──────────────────────────────────────────────────
# Sets the default AI backend used when you ALSO pass --explain-with-ai on the
# command line. Off unless you opt in with that flag. Choices: ollama | claude | openai.
ai:
  provider: ollama
```

You can save this exact file and scan with it — it parses cleanly. The config file may
be named `.njordscan.yml`, `.njordscan.yaml`, or `njordscan.yml`.

### Where NjordScan looks for the file

By default NjordScan auto-detects the config. It looks in the directory you're scanning,
then walks **up** through parent directories, stopping at the repo root (the folder
containing `.git`). So a single `.njordscan.yml` at the top of your repo applies to scans
of any sub-folder inside it.

You can steer this:

```bash
njordscan scan . --config path/to/.njordscan.yml   # use a specific file
njordscan scan . --no-config                        # ignore all config files
```

---

## How command-line flags override the file

The rule of thumb: **a flag you type on the command line beats the file.** That lets you
keep your shared defaults in `.njordscan.yml` and still tweak a single run when you need
to. Here's exactly how each setting behaves:

| Config key | Command-line flag | When both are set… |
|---|---|---|
| `min_severity` | `--min-severity` | The flag wins (unless you leave it at the default `info`, in which case the file's value applies). |
| `fail_on` | `--fail-on` | The flag wins. |
| `ignore` | `--ignore` | **Added together** — both the file globs and the flag globs apply. |
| `skip_detectors` | `--skip` | **Added together** — both lists are skipped. |
| `only_detectors` | `--only` | The flag wins (replaces the file's list). |
| `disable_rules` | *(file only)* | No flag; set it in the file. |
| `severity` | *(file only)* | No flag; set it in the file. |
| `baseline` | `--baseline` | The flag wins. |
| `ai.provider` | `--ai-provider` | The flag wins (only used when `--explain-with-ai` is on). |

A worked example. Suppose your committed `.njordscan.yml` says:

```yaml
min_severity: critical
```

A normal scan only shows critical findings:

```bash
njordscan scan .
# NjordScan: 1 issue(s) — 1 critical, 0 high, 0 medium, 0 low.
```

But for one run you want to see the highs too — override on the command line:

```bash
njordscan scan . --min-severity high
# NjordScan: 2 issue(s) — 1 critical, 1 high, 0 medium, 0 low.
```

The file is untouched; only this run changed.

---

## Picking detectors: `--only` and `--skip`

A **detector** is one family of checks. The nine detector ids are:

| id | What it looks for |
|---|---|
| `secrets` | Hard-coded API keys, passwords, tokens, private keys. |
| `supply-chain` | Risky/typo-squatted packages and install scripts. |
| `dependencies` | Known CVEs in your installed packages. |
| `static` | Unsafe code patterns (XSS sinks, etc.) read straight from source. |
| `taint` | Untrusted input that flows into a dangerous sink. |
| `configs` | Insecure framework settings (Next.js, Vite, headers). |
| `patterns` | A large library of regex-based "smells". |
| `git-hygiene` | Secrets or junk committed to git history / `.gitignore` gaps. |
| `runtime` | Runtime/environment hardening checks. |

Run **only** some of them:

```bash
njordscan scan . --only secrets,taint      # just these two
njordscan scan . --only secrets --only taint   # same thing, repeated flag
```

Run everything **except** some:

```bash
njordscan scan . --skip dependencies,supply-chain
njordscan scan . --skip dependencies --skip supply-chain   # same thing
```

Both flags accept a comma-separated list **or** the flag repeated — use whichever you
like. In a config file these become `only_detectors:` and `skip_detectors:`.

> Tip: `--mode quick` is a shortcut that skips the two heaviest detectors (`taint` and
> `dependencies`) for fast feedback while you code. `--mode standard` (the default) and
> `--mode deep` run everything that applies. See the [README](../README.md) for the full
> flag list.

---

## Ignoring files and folders: `--ignore` globs

NjordScan already skips the obvious noise (like `node_modules`). To skip more, give it
glob patterns — either in the file or on the command line:

```yaml
# .njordscan.yml
ignore:
  - "**/legacy/**"     # an old area you'll fix later
  - "**/*.min.js"      # minified bundles
  - "src/generated/**" # auto-generated code
```

```bash
njordscan scan . --ignore "src/generated/**" --ignore "**/*.min.js"
```

Remember that `--ignore` is **additive**: command-line globs are added to the ones in
your file, not swapped in. Globs match paths relative to the project, and `**` matches
across directory levels.

---

## Silencing one finding on one line: `njordscan-ignore`

Sometimes a single line trips a check and you've genuinely reviewed it — the input is
already sanitized, say. Instead of disabling the whole rule everywhere, leave a comment
on that exact line containing `njordscan-ignore`:

```js
const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY; // njordscan-ignore: server-only build, stripped from client
const key2 = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
```

Now only the second line is reported. The marker `nosec` works the same way, for
compatibility with other tools:

```js
apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, // nosec
```

It's good manners to add a short note after the marker explaining *why* it's safe — your
future teammates will thank you.

> Heads-up: the per-line `njordscan-ignore` / `nosec` marker is honored by the
> pattern-based checks (the `patterns` detector and the regex rule library). A few
> deeper code-flow checks don't read line comments — for those, silence the rule with
> `disable_rules:` in your config, or scope it out with an `ignore:` glob.

---

## Showing fewer findings: `--min-severity`

Severity goes, lowest to highest: **info → low → medium → high → critical**.
`--min-severity` (or `min_severity:` in the file) hides everything quieter than the
level you pick. It changes what's *shown*; it does not change what *fails* a build —
that's `--fail-on`.

```bash
njordscan scan . --min-severity medium   # hide info and low findings
```

```yaml
# .njordscan.yml
min_severity: low   # the default is info (show everything)
```

If you want to both hide the small stuff *and* gate your CI, combine them:

```yaml
min_severity: low    # don't bother me with info-level notes
fail_on: high        # but fail the build on high/critical
```

---

## Exit codes (for scripts and CI)

`njordscan scan` tells your automation what happened through its exit code:

| Code | Meaning |
|---|---|
| `0` | Clean — no findings, or nothing met your `fail_on` level. |
| `1` | A finding was at or above `fail_on` (the gate tripped). |
| `2` | The scan itself errored (bad path, unreadable project, etc.). |

So a typical CI step is just:

```bash
njordscan scan . --fail-on high
```

Anything high or critical fails the job; everything else passes. For the full CI and
pull-request workflow (GitHub Actions, pre-commit, `--diff`, baselines), see the
[README](../README.md).

---

## Adopting NjordScan into an existing project (`baseline`)

If you run NjordScan on a mature codebase for the first time, you may get a wall of
findings. A **baseline** lets you draw a line under what's there today and only get
alerted about *new* problems going forward.

Set the path in your config (or pass `--baseline PATH`):

```yaml
# .njordscan.yml
baseline: .njordscan-baseline.json
```

Record the current findings once:

```bash
njordscan scan . --update-baseline
# ✓ Baseline updated: 12 finding(s) recorded in .njordscan-baseline.json
```

From now on, known findings are hidden and only new ones show up (and can fail the
build):

```bash
njordscan scan .
# (12 known finding(s) hidden by baseline.)
```

Commit the baseline file so your team shares it. Re-run `--update-baseline` whenever you
clean up old issues and want to reset the line.

---

## A complete, opinionated example

Here's a config a small team might actually commit — sensible noise control, a CI gate,
a couple of reviewed exceptions, and a baseline:

```yaml
# .njordscan.yml
min_severity: low                  # skip purely informational notes
fail_on: high                      # CI fails on high or critical

ignore:
  - "**/legacy/**"                 # being rewritten this quarter
  - "**/*.min.js"

disable_rules:
  - react.unsafe-target-blank      # reviewed 2026-05; not exploitable in our setup

severity:
  xss.inner-html: critical         # we treat any HTML-injection sink as top priority

baseline: .njordscan-baseline.json
```

Run it with a plain `njordscan scan .` and everyone — laptops and CI alike — gets the
same result. When you need a one-off variation, reach for a flag and it'll override the
file for that run.

---

## See also

- **[Getting started](getting-started.md)** — install and your first scan.
- **[Rules catalog](RULES.md)** — every rule, why it matters, and how to fix it.
- **[Using NjordScan with AI assistants (MCP)](ai-assistant-mcp.md)** — wire it into
  Claude Code and friends.
- **[Project README](../README.md)** — full flag reference, CI/CD, DAST, and AI options.

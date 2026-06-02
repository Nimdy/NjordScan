# Getting started with NjordScan

NjordScan is a security scanner for **Next.js, React, and Vite** apps, built for
developers who are *not* security experts. Point it at your project and it tells you,
in plain English, where your code might be unsafe — *why* it matters and *how* to fix
it — without expecting you to already know what a vulnerability like XSS is. If you can
run a terminal command, you can use NjordScan.

## Install

NjordScan is a Python package. The cleanest way to install it is in a virtual
environment so it doesn't clash with anything else on your machine:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install njordscan
```

The core install is tiny (no heavyweight ML dependencies). Check it worked:

```bash
njordscan version
```

You should see something like `NjordScan v2.0.0b1`.

## Your first scan

`cd` into the project you want to check and run:

```bash
njordscan scan .
```

The `.` means "scan this directory" — it's the default, so `njordscan scan` on its own
does the same thing. NjordScan walks your code, runs its detectors, and prints a report.
That's it. No config, no account, no setup.

> NjordScan scans the files on disk; it never runs your app or makes network calls
> against it (unless you explicitly ask for a [dynamic scan](#whats-next) with `--url`).

## How to read the report

The report opens with a header (files scanned, time taken) and a **Summary** box
counting findings by severity. Then each finding gets its own panel. Here's a real one,
trimmed:

```
╭─  1. 🟠 [HIGH] User input assigned to innerHTML / outerHTML ─────────────────╮
│                                                                              │
│  app.js:3                                                                    │
│  CWE-79  ·  A03:2021-Injection  ·  confidence: medium                        │
│                                                                              │
│  innerHTML assigned a non-literal value; renders as HTML and can execute     │
│  injected scripts if user-controlled.                                        │
│                                                                              │
│  Found here:                                                                 │
│    el.innerHTML = userInput;                                                 │
│                                                                              │
│  💡 Why this matters                                                         │
│  Assigning a string to `element.innerHTML` parses it as HTML. When the       │
│  string contains data an attacker controls, they can inject markup that      │
│  runs JavaScript in your users' browsers (cross-site scripting)...           │
│                                                                              │
│  🛠  How to fix it                                                            │
│  Use `element.textContent` to insert text safely...                          │
│    element.textContent = userInput; // rendered as text, never executed      │
│                                                                              │
│  📚 Learn more                                                               │
│     • https://owasp.org/www-community/attacks/xss/                           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Every panel has the same shape, so once you've read one you've read them all:

- **The title** — the severity (🔴 critical, 🟠 high, 🟡 medium, and lower) and a
  short description of the problem.
- **The location** — `app.js:3` is the exact `file:line`. Jump straight there.
- **CWE / OWASP tags + confidence** — standard security IDs (handy if you want to read
  more) and how sure NjordScan is. `confidence: medium` means "worth a look."
- **💡 Why this matters** — plain-English explanation of what could go wrong. No jargon.
- **🛠 How to fix it** — concrete advice plus a corrected code snippet you can copy.
- **📚 Learn more** — a link to a trustworthy write-up if you want the full story.

If you only want the headline numbers, add `--quiet` for a one-line summary, or
`--min-severity high` to hide the lower-priority noise while you focus on the big stuff.

## Every finding explains itself

This is the whole point of NjordScan: you should never have to Google a finding to
understand it. The explanation is right there in the report. And if you want to go
deeper — say, before fixing a class of bug across your codebase — ask for the full
walk-through of any rule by its ID:

```bash
njordscan explain secret.generic
```

That prints the same "why it matters / how to fix it" guidance plus a secure example,
standalone, for any rule. Run `njordscan explain` with no argument to list every rule
NjordScan knows. The complete catalog also lives in [RULES.md](./RULES.md).

## Exit codes (so it fits in scripts)

NjordScan uses standard exit codes, which matter the moment you put it in a script or CI:

| Code | Meaning |
|------|---------|
| `0`  | Clean — no findings, *or* nothing at or above your `--fail-on` threshold. |
| `1`  | A finding met your `--fail-on` level (a real failure to act on). |
| `2`  | The scan itself couldn't run (e.g. a path that doesn't exist). |

Note that **a plain `njordscan scan .` exits `0` even when it finds issues** — it's
showing you a report, not failing a build. You opt into build-failing behavior with
`--fail-on` (see below). Check the code in bash with `echo $?` right after a scan.

## What's next

You've got the basics. Here are three things to try in the next 60 seconds:

1. **Let it fix the easy stuff.** Some findings have safe, automatic fixes:

   ```bash
   njordscan scan . --fix --dry-run   # preview the changes
   njordscan scan . --fix             # apply them
   ```

   `--fix` only applies *safe, additive* fixes; `--dry-run` shows the diff first so
   nothing happens behind your back. If there's nothing auto-fixable, it'll say so.

2. **Wire it into CI.** Make the build fail only on serious findings:

   ```bash
   njordscan scan . --fail-on high
   ```

   This exits `1` if anything high or critical shows up — perfect for a CI step or a
   pre-commit hook. On a pull request, `njordscan scan . --diff` reports only issues on
   the lines you changed, so you're not blamed for old problems.

3. **Make it yours.** Generate a starter config you can tweak (ignore paths, set a
   default `fail_on`, turn rules off):

   ```bash
   njordscan init       # writes a starter .njordscan.yml
   ```

   NjordScan auto-detects that file on future scans. CLI flags always win over the file.

### Going further

- **`njordscan doctor`** — prints what's installed and working (detectors, rule counts,
  advisory freshness). Run it if anything seems off.
- **Optional AI explanations** — add `--explain-with-ai` for an AI-written second
  opinion on each finding. The built-in explanations are always on; this just adds an
  LLM rewrite. See the README's
  [Plain-English explanations](../README.md#plain-english-explanations-the-whole-point)
  section.
- **Dynamic scanning (`--url`)** — also probe a *running* site for things like missing
  security headers and reflected XSS. See
  [Dynamic scanning (DAST)](../README.md#dynamic-scanning-dast) in the README.
- **Use it from your AI assistant** — NjordScan can run as an
  [MCP server](../README.md#use-it-with-your-ai-coding-assistant-mcp) so tools like
  Claude Code can scan and explain for you.

For the big picture and every flag, see the [README](../README.md). For the full list of
what NjordScan checks, see [RULES.md](./RULES.md). Happy (and safer) shipping. 🛡

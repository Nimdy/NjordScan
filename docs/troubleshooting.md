# Troubleshooting & FAQ

Stuck on something? This page answers the questions we hear most. It's written in
plain English — you don't need to be a security expert to follow along.

Every command below is real and copy-pasteable. If you ever want to double-check
what your install can do, run `njordscan doctor` (more on that at the
[bottom of this page](#q-how-do-i-check-my-install-is-healthy)).

New here? Start with the [Getting started guide](getting-started.md). Want the full
list of things NjordScan looks for? See the [Rules catalog](RULES.md). For the big
picture, see the [README](../README.md).

---

## Q: `--url` does nothing / "needs njordscan[dynamic]"

The `--url` flag turns on **dynamic scanning** — NjordScan actually talks to your
running app over HTTP to check things you can only see live (security headers,
cookie flags, reflected inputs, and so on). That extra ability ships separately so
the core install stays tiny.

If you see a message like this:

```
--url needs the dynamic extra: pip install 'njordscan[dynamic]' — running static scan only.
```

…it means the dynamic part isn't installed. The scan still runs — it just skips the
live checks. To enable them:

```bash
pip install 'njordscan[dynamic]'
```

Then point it at your app while it's running:

```bash
# start your dev server in another terminal first, e.g. npm run dev
njordscan scan . --url http://localhost:3000 --allow-private
```

Two things to know:

- **`--allow-private` is required for `localhost` / `127.0.0.1` / private IPs.**
  Without it, NjordScan refuses to connect and prints
  `runtime: refusing to scan private/loopback host localhost (use --allow-private)`.
  This is a safety feature (it stops the scanner from being tricked into poking
  internal machines). For a local dev server, just add the flag.
- **It only sends safe, read-only requests.** No data is changed, and TLS
  certificates are verified. See the [Dynamic scanning guide](ai-assistant-mcp.md)
  context in the [README](../README.md#dynamic-scanning-dast) for the full list of
  what it probes.

---

## Q: AI explanations say "unavailable" / how do I turn them on?

First, the good news: **plain-English explanations are always on.** Every finding
already comes with a "Why this matters" and "How to fix it" written for humans — no
flag, no AI, no setup. That's the whole point of NjordScan.

The `--explain-with-ai` flag is an *optional extra* that asks a language model to
rewrite the explanation for your specific code. It needs two things:

**1. The AI extra installed:**

```bash
pip install 'njordscan[ai]'
```

**2. A working AI backend.** The default is [Ollama](https://ollama.com) — a free,
local model that keeps everything on your machine (nothing is uploaded). If Ollama
isn't running, you'll see:

```
AI explanations unavailable: Ollama not reachable at http://127.0.0.1:11434. Install it from https://ollama.com, then run:  ollama pull qwen2.5-coder:7b
Falling back to the built-in offline explanations (already shown).
```

The fix is right there in the message — install Ollama, then pull a model:

```bash
ollama pull qwen2.5-coder:7b
njordscan scan . --explain-with-ai
```

Prefer a hosted model instead? You can point at Claude or OpenAI:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
njordscan scan . --explain-with-ai --ai-provider claude

export OPENAI_API_KEY=sk-...
njordscan scan . --explain-with-ai --ai-provider openai
```

When you use a hosted provider, NjordScan **redacts secrets out of your code before
sending it** (you can override that with `--no-redact`, but you usually shouldn't).
Either way, if the AI call fails, the scan still finishes and you keep the built-in
offline explanations. Full details in the [AI features guide](ai-features.md).

---

## Q: I got **no findings** — is something broken?

Probably not — that's by design. **A clean app produces zero findings**, so a clean
result is meant to be trustworthy, not suspicious. You'll see:

```
╭──────────────────────────────── ✅ All clear ────────────────────────────────╮
│  No security issues found.                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

A few sanity checks if zero still feels surprising:

- **Did it scan the right place?** The line under the banner shows the path and a
  file count (e.g. `· 1 files`). If that count is `0`, you may have pointed at an
  empty or wrong directory — pass the project root explicitly: `njordscan scan ./my-app`.
- **Did you narrow the scan?** If you used `--only`, `--skip`, `--min-severity`, a
  `--baseline`, or `--diff`, you may have filtered findings out on purpose. Run a
  plain `njordscan scan .` to see everything.
- **Remember no scanner catches everything.** Keep dependencies updated and review
  anything that handles user input. NjordScan tells you this in the "All clear" box
  too.

---

## Q: Way **too many findings** on an existing project

This is completely normal the first time you scan a project that's been around for a
while. You have three good options, and you can combine them.

**1. Set a baseline — accept what's there today, only flag what's new.**
This is the recommended way to adopt NjordScan into an existing codebase.

```bash
# Record everything you have right now as "known / accepted"
njordscan scan . --baseline .njordscan-baseline.json --update-baseline

# From now on, only brand-new findings show up (and can fail CI)
njordscan scan . --baseline .njordscan-baseline.json
```

Commit the baseline file. After that, the existing noise is hidden and you only deal
with issues your team introduces going forward.

**2. Only scan what changed in this branch/PR.**
Great for pull requests — it reports issues on changed lines only:

```bash
njordscan scan . --diff            # vs HEAD
njordscan scan . --diff main       # vs the main branch
```

**3. Raise the floor with `--min-severity`.**
Hide the lower-priority stuff and focus on the serious findings first:

```bash
njordscan scan . --min-severity high
```

For CI setups using these, see the [CI/CD & PRs guide](ci-cd.md).

---

## Q: How do I silence **one specific finding**?

You have two clean ways, depending on how broad you want the silence to be.

**1. Silence a single line in the code** — add a `njordscan-ignore` (or `nosec`)
comment on the offending line:

```js
const client = new OpenAI({ dangerouslyAllowBrowser: true }); // njordscan-ignore
```

Both `njordscan-ignore` and `nosec` work. Use this when *that exact spot* is a
reviewed, intentional exception. (Note: this marker applies to the pattern-based
rules — the kind that match on a line of code.)

**2. Silence a rule everywhere** — list its rule ID under `disable_rules` in your
`.njordscan.yml`:

```yaml
# .njordscan.yml
disable_rules:
  - ai.dangerously-allow-browser
```

Use this when you've decided a whole *category* of finding doesn't apply to your
project. Not sure of the rule ID? It's printed with every finding, and you can look
any of them up:

```bash
njordscan explain ai.dangerously-allow-browser   # full write-up for one rule
njordscan explain                                 # list every rule + ID
```

Don't have a config file yet? Create a starter with `njordscan init` (see the
[silencing a whole project](#q-how-do-i-create-a-config-file) question below).

---

## Q: Taint analysis isn't catching something I expected

The taint detector traces untrusted data (like a URL parameter) as it flows through
your code into a dangerous "sink" (like `eval`). It's powerful, but it works by
**static heuristics** — it reads your code without running it, so it can't follow
every possible path (dynamic dispatch, data that round-trips through a database, very
indirect flows, etc.). That's a normal limitation of this kind of analysis, not a
bug.

If you suspect something is slipping through:

- **Run the live checks too.** The dynamic scan actually exercises your running app
  and can catch reflected-input issues that static analysis misses:

  ```bash
  njordscan scan . --url http://localhost:3000 --allow-private
  ```

  (Needs `pip install 'njordscan[dynamic]'` — see the [`--url` question](#q---url-does-nothing--needs-njordscandynamic) above.)
- **Make sure you're not in quick mode.** `--mode quick` deliberately skips the
  heavier `taint` and `dependencies` detectors for speed. Use the default
  `--mode standard` (or `--mode deep`) to run taint analysis:

  ```bash
  njordscan scan . --mode standard
  ```
- **Check the taint engine is available** with `njordscan doctor` — the
  `Taint engine` line should say `tree-sitter available`.

---

## Q: How do I run just **one check** (or skip one)?

Use `--only` to run a single detector (or a few), and `--skip` to leave some out.
Both accept a comma-separated list or can be repeated.

```bash
njordscan scan . --only secrets                 # just hunt for hard-coded secrets
njordscan scan . --only secrets,patterns        # a couple of detectors
njordscan scan . --skip dependencies,taint      # everything except these
```

The detector IDs are:
`secrets`, `supply-chain`, `dependencies`, `static`, `taint`, `configs`,
`patterns`, `git-hygiene`, `runtime`.

This is handy for fast, focused runs — e.g. `--only secrets` before a commit to make
sure you didn't paste an API key.

---

## Q: How do I create a config file?

Generate a fully commented starter and edit it to taste:

```bash
njordscan init           # writes .njordscan.yml in the current directory
njordscan init ./my-app  # …or in another directory
njordscan init --force   # overwrite an existing one
```

The file supports `min_severity`, `fail_on`, `ignore` (globs), `skip_detectors`,
`only_detectors`, `disable_rules`, `severity` (re-map a rule's severity),
`baseline` (a path), and an `ai:` block. **CLI flags always override the file**, and
`--no-config` ignores the file entirely for a one-off run. See the
[README's configure section](../README.md#configure-njordscanyml) for the full
key list.

---

## Q: My dependency / CVE findings look out of date

NjordScan ships with a seed database of known-vulnerable packages, plus a cache it
keeps on your machine. Refresh that cache from [OSV.dev](https://osv.dev) any time:

```bash
njordscan update
```

You'll see something like:

```
Refreshing advisories for 53 packages from OSV.dev…
✓ 362 advisories for 49 packages → /home/you/.njordscan/advisories.json
```

The data lands in `~/.njordscan/advisories.json`. Run it periodically (or in a
scheduled CI job) to stay current. `njordscan doctor` shows how fresh your advisory
data is on the `Advisories` line.

---

## Q: The scan **exited with an error code** in CI — what does it mean?

NjordScan uses three exit codes so CI can react correctly:

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean — no findings at or above your `--fail-on` threshold. |
| `1` | A finding met your `--fail-on` level (this is the "fail the build" signal). |
| `2` | The scan itself couldn't run — e.g. a bad path or a real error. |

By default a scan that *finds* issues still exits `0` (so it's informational). To
make CI fail on real problems, set a threshold:

```bash
njordscan scan . --fail-on high   # exit 1 if anything is high or critical
```

If you're getting a `2`, double-check the target path exists — pointing at a missing
directory is the most common cause:

```bash
njordscan scan ./does-not-exist   # → exits 2
```

More CI recipes (GitHub Actions, pre-commit) are in the
[CI/CD & PRs guide](ci-cd.md).

---

## Q: How do I check my install is healthy?

Run the built-in self-check — it's the fastest way to see exactly what your copy of
NjordScan can do:

```bash
njordscan doctor
```

You'll get a readout like this:

```
  NjordScan       v2.0.0b1
  Python          3.12.3
  Detectors       secrets, supply-chain, dependencies, static, taint, configs,
                  patterns, git-hygiene, runtime
  Rules           121
  Patterns        127
  Advisories      shipped seed + user cache (53 pkgs from osv.dev)
  Taint engine    tree-sitter available
  AI explain      httpx installed; no Anthropic key; no OpenAI key
```

How to read it:

- **Detectors / Rules / Patterns** — confirms the rule library loaded.
- **Advisories** — how fresh your CVE data is (refresh with `njordscan update`).
- **Taint engine** — should say `tree-sitter available`; if not, taint analysis is
  limited.
- **AI explain** — tells you whether the AI extra (`httpx`) is installed and which
  provider keys it can see. If this line says `httpx missing`, that's your cue to run
  `pip install 'njordscan[ai]'` for `--explain-with-ai`.

---

## Still stuck?

- Check the [Getting started](getting-started.md), [AI features](ai-features.md),
  and [AI assistant / MCP](ai-assistant-mcp.md) guides.
- Browse every rule (with plain-English explanations) in the
  [Rules catalog](RULES.md), or run `njordscan explain <rule-id>`.
- Read the [README](../README.md) for the full feature tour.

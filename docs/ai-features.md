# AI features

NjordScan has **two completely separate** AI features, and it's worth getting the
difference clear up front because people mix them up:

1. **AI application security** — rules that scan *your* code for risky ways of
   using an LLM (OpenAI, Anthropic, etc.). These find problems like leaking your
   API key to the browser, or running whatever the model says without checking it.
   **They run automatically. No setup, no key, no internet.**

2. **AI-powered explanations** — an *optional* feature where NjordScan asks an LLM
   to rewrite a finding's explanation for you, on top of the plain-English
   explanation it always shows. **This is off by default.** You turn it on with
   `--explain-with-ai`, and you choose whether that LLM runs on your own machine
   or in the cloud.

The first is about **finding** AI-related bugs in your app. The second is about
**explaining** any finding using AI. Don't confuse "NjordScan uses AI" with
"NjordScan scans AI code" — it does the second always, and the first only if you ask.

> **Privacy in one sentence:** nothing leaves your machine unless you explicitly
> pass `--explain-with-ai` *with a cloud provider* (`claude` or `openai`). Everything
> else — including the always-on explanations and the AI-app rules below — is 100% local.

---

## Part 1 — AI application security (always on)

If your app calls an LLM, you've got a new attack surface that most security
tools ignore. NjordScan ships a set of `ai.*` rules built for exactly this, and
they run as part of a normal scan — you don't need to do anything special:

```bash
njordscan scan .
```

These rules live in the `static` and `patterns` detectors, so even a quick scan
catches most of them:

```bash
njordscan scan . --mode quick
```

Want to see *only* the AI-app findings while you're working on that part of the
code? Run the two detectors that carry them:

```bash
njordscan scan . --only static,patterns
```

### What it looks for

Here's the full set, grouped by the kind of mistake. Every one is explained in
plain English in the report and in the [rules catalog](RULES.md#ai--llm-application-security).

**Your secret key ends up where strangers can grab it**

| Rule | Severity | The mistake |
|------|----------|-------------|
| `ai.key-clientside` | 🔴 critical | Your OpenAI/Anthropic key is in browser code (or behind a `NEXT_PUBLIC_` / `VITE_` prefix that bundles it into the JavaScript every visitor downloads). Anyone can open devtools and spend your money. |
| `ai.dangerously-allow-browser` | 🟠 high | The OpenAI SDK started with `dangerouslyAllowBrowser: true`. The SDK refuses to run in the browser *on purpose* because it leaks your key; this flag overrides that safety. The word "dangerously" is the warning. |
| `ai.system-prompt-clientside` | 🟡 medium | Your hidden system prompt / instructions are defined in `'use client'` code, so anyone can read them in the bundle. |

**You trust what the model says a little too much**

| Rule | Severity | The mistake |
|------|----------|-------------|
| `ai.llm-output-to-sink` | 🔴 critical | The model's reply is passed straight to `eval()`, a shell, or a SQL query. A user can steer the model into producing a payload that then runs on your server — full takeover. |
| `ai.llm-output-rendered-as-html` | 🟠 high | The model's reply is rendered as raw HTML (`dangerouslySetInnerHTML` / `innerHTML`). If the model emits a `<script>`, that's cross-site scripting (XSS) — an attacker's code running in your users' browsers. |
| `ai.prompt-injection` | 🟠 high | User input is glued directly into the system/instruction prompt (with `+` or `${...}`). A user can write "ignore your previous instructions" and the model obeys. This is the #1 risk for AI apps. |

**Anyone on the internet can run up your bill ("denial of wallet")**

| Rule | Severity | The mistake |
|------|----------|-------------|
| `ai.endpoint-no-auth` | 🟠 high | A route that calls a paid model has no sign-in check, so anyone who finds the URL can hammer it and drain your account overnight. |
| `ai.no-rate-limit` | 🟡 medium | The route calls the model with no rate limit — even a friendly retry-loop bug can run up a huge bill. |
| `ai.unbounded-output` | 🔵 low | The model call sets no max output token limit, so each response can be (and be billed as) far larger than you expect. |

**You send the model things it never needed**

| Rule | Severity | The mistake |
|------|----------|-------------|
| `ai.pii-or-secret-to-llm` | 🟡 medium | Secrets or personal data are sent into a prompt. The model doesn't need them, and a prompt-injection attack can read them back. |

> There's also one **live** AI rule, `ai-endpoint.unauthenticated-live`, that
> actually pokes your running app's `/api/chat`-style endpoints to confirm they
> answer unauthenticated requests. That one only fires during a dynamic scan
> (`njordscan scan . --url https://staging.example.com`) and needs the
> `njordscan[dynamic]` extra. The static `ai.endpoint-no-auth` above catches the
> same problem by reading your source — no running app required.

### See it work

Drop this into `app/api/chat/route.ts` — it packs several of the mistakes above
into one file:

```ts
import OpenAI from "openai";
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export async function POST(req: Request) {
  const { userInput } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "system", content: "You are a bot. " + userInput }],
  });
  const text = completion.choices[0].message.content;
  eval(text);                       // running whatever the model said — never do this
  return Response.json({ text });
}
```

Scan it:

```bash
njordscan scan .
```

NjordScan flags the `eval()` of model output (critical), the unauthenticated AI
route, the `dangerouslyAllowBrowser: true`, and the user input concatenated into
the system prompt (prompt injection) — each with a why-this-matters and a copy-paste fix.

### Dig deeper into any AI rule

Every rule has a full write-up you can read in your terminal, no finding required:

```bash
njordscan explain ai.prompt-injection
njordscan explain ai.llm-output-to-sink
njordscan explain               # lists every rule NjordScan knows
```

---

## Part 2 — AI-powered explanations (opt-in)

Here's the important bit: **NjordScan already explains every finding in plain
English, with no AI and no internet.** Those built-in, offline explanations are
*always on*. You don't need a flag, a key, or a network connection to get the
"why this matters" and "how to fix it" sections — that's just how a normal scan
looks.

`--explain-with-ai` doesn't *replace* those explanations. It **adds** an LLM
rewrite on top of them. Some people find an AI rewrite tailored to their exact
code snippet easier to act on; if that's you, this is the flag. If not, you lose
nothing by ignoring it.

```bash
# the explanations you already get — offline, always
njordscan scan .

# the same, plus an extra AI-written pass on each finding
njordscan scan . --explain-with-ai
```

### Choosing where the AI runs

`--explain-with-ai` uses a provider, set with `--ai-provider`. **The default is
`ollama`, which runs a model locally on your own machine** — private, free, and
offline. You only reach the cloud if you explicitly choose `claude` or `openai`.

| Provider | `--ai-provider` | Runs where | Needs |
|----------|-----------------|-----------|-------|
| Ollama (default) | `ollama` | **Your machine** — nothing leaves it | A running [Ollama](https://ollama.com) with a model pulled |
| Anthropic Claude | `claude` | Anthropic's API (cloud) | `ANTHROPIC_API_KEY` env var |
| OpenAI | `openai` | OpenAI's API (cloud) | `OPENAI_API_KEY` env var |

**Local (default, private):**

```bash
# uses Ollama on localhost — "Nothing leaves your machine."
njordscan scan . --explain-with-ai
njordscan scan . --explain-with-ai --ai-provider ollama   # same thing, explicit
```

Two environment variables tune the local provider:

- `OLLAMA_HOST` — where Ollama is listening (default `http://localhost:11434`)
- `NJORDSCAN_AI_MODEL` — which model to use (default `qwen2.5-coder:7b`)

```bash
ollama pull qwen2.5-coder:7b                 # one-time: get the model
NJORDSCAN_AI_MODEL=llama3.1 njordscan scan . --explain-with-ai
```

**Cloud (opt-in, needs a key):**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
njordscan scan . --explain-with-ai --ai-provider claude

export OPENAI_API_KEY=sk-...
njordscan scan . --explain-with-ai --ai-provider openai
```

### It fails safe

If the AI can't be reached — Ollama isn't running, the model isn't pulled, or a
cloud key is missing — NjordScan tells you why and **falls back to the offline
explanations you already have.** Your scan never breaks because of an AI hiccup:

```
AI explanations unavailable: claude needs the ANTHROPIC_API_KEY environment variable to be set.
Falling back to the built-in offline explanations (already shown).
```

```
AI explanation failed: Ollama request failed: ... Is the model pulled?  Try:  ollama pull qwen2.5-coder:7b
Falling back to the built-in offline explanations (already shown).
```

### Privacy and redaction

This is the part people care about most, so it's worth being precise:

- **The default provider (`ollama`) is local.** When NjordScan uses it, it prints
  `🔒 Explaining N finding(s) with a local model ... Nothing leaves your machine.`
  No code, no findings, nothing touches the network.

- **Only the cloud providers send anything off your machine**, and they only do
  so for the finding's small code snippet (so the model has context). **Before
  sending, NjordScan redacts anything that looks like a secret** — API keys,
  credentials in URLs, and similar — replacing them with a `‹redacted›` marker.
  When a cloud provider is used you'll see a notice like
  `☁  Sending N finding(s) with code context to ... — secrets redacted.`

- **`--no-redact`** turns that redaction *off*, sending the snippet exactly as
  written. Only use this if you trust the provider and need the raw code in the
  explanation; the notice will warn you in red that code is being sent un-redacted.
  It has no effect with the local `ollama` provider (nothing is sent anyway).

- **`--no-external`** is the belt-and-suspenders switch: it hard-blocks any remote
  provider, so even `--ai-provider claude` will simply skip the cloud and keep
  everything local. Use it in locked-down environments where no code may leave the
  machine, ever.

```bash
# cloud, but secrets stripped from snippets first (this is the default behaviour)
njordscan scan . --explain-with-ai --ai-provider claude

# cloud, snippets sent exactly as written — opt in only if you mean it
njordscan scan . --explain-with-ai --ai-provider claude --no-redact
```

**The privacy-maximizing choice is simply the default:** use `ollama` (or just
don't pass `--explain-with-ai` at all) and not a single byte leaves your laptop.

### Installing the AI extra

The AI-explanation feature needs one small extra dependency (`httpx`). Install it
with the `[ai]` extra:

```bash
pip install njordscan[ai]
```

Check what's available any time:

```bash
njordscan doctor
```

The `AI explain` line tells you whether `httpx` is installed and whether your
cloud keys are set, e.g. `httpx installed; no Anthropic key; no OpenAI key`.

### Setting a default in config

If you always want the same provider, set it once in `.njordscan.yml` instead of
typing the flag every time (run `njordscan init` to create a starter file):

```yaml
# Optional AI explanations (off unless you also pass --explain-with-ai)
ai:
  provider: ollama   # ollama | claude | openai
```

This only chooses the *provider* — you still pass `--explain-with-ai` to turn the
feature on. CLI flags always override the file.

---

## Quick reference

| I want to... | Command |
|--------------|---------|
| Scan my app, including AI-code risks (offline) | `njordscan scan .` |
| See only the AI-app findings | `njordscan scan . --only static,patterns` |
| Read the full write-up for an AI rule | `njordscan explain ai.prompt-injection` |
| Add a local AI rewrite to each finding (private) | `njordscan scan . --explain-with-ai` |
| Add a cloud AI rewrite (Claude) | `ANTHROPIC_API_KEY=... njordscan scan . --explain-with-ai --ai-provider claude` |
| Check what AI bits are installed | `njordscan doctor` |

## See also

- [Rules catalog](RULES.md#ai--llm-application-security) — every `ai.*` rule with full why + fix
- [AI coding assistants (MCP)](ai-assistant-mcp.md) — let Claude Code / Cursor scan inline as you build
- [Documentation index](README.md) and the [project README](../README.md)

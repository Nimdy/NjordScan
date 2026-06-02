# Dynamic scanning (DAST) with `--url`

Most of NjordScan reads your **code** — your files, your `package.json`, your config.
That's *static* analysis, and it's the default. But some problems only appear once your
app is actually **running and answering requests**: the real headers it sends, whether
its cookies are locked down, whether a URL parameter gets echoed straight back into the
page. To catch those, you point NjordScan at a live, running app with `--url`. That's
**dynamic scanning** — often called **DAST** (Dynamic Application Security Testing).

You don't need to be a security expert to use it. You give it a web address, it makes a
handful of polite, harmless requests, and it tells you in plain English what it noticed.

---

## Install the dynamic extra

Static scanning needs nothing extra. Dynamic scanning makes real HTTP requests, so it
needs one small extra (the `httpx` HTTP client). Install it once:

```bash
pip install 'njordscan[dynamic]'
```

The quotes matter in zsh and most shells — `[dynamic]` can otherwise be misread as a
glob pattern.

Not sure if it's installed? Run `njordscan doctor` and look at the **AI explain** line —
if it says `httpx installed`, you already have everything dynamic scanning needs (the
`[ai]` and `[dynamic]` extras both provide `httpx`). If `--url` ever can't find it, it
just prints a friendly reminder and skips the dynamic part rather than crashing.

---

## Run it

The shape is: scan your code **and** dynamically probe a running copy of the app, in one
command.

```bash
njordscan scan . --url https://staging.myapp.com
```

That does two things at once:

1. **Static scan** of the project in `.` (your code, dependencies, config — the usual).
2. **Dynamic scan** of the live site at `https://staging.myapp.com`.

Dynamic findings show up in the same report as everything else, but their "location" is a
**URL** instead of a file and line number, so they're easy to spot:

```
╭─  1. 🟡 [MEDIUM] No Content-Security-Policy header ──────────────────────────╮
│  https://example.com                                                         │
│  CWE-693  ·  A05:2021-Security Misconfiguration  ·  confidence: high         │
│  Response has no Content-Security-Policy header.                             │
╰──────────────────────────────────────────────────────────────────────────────╯
```

If you only want the dynamic checks (and not the code scan), scope the run to the
`runtime` detector — that's the one that does DAST:

```bash
njordscan scan . --url https://staging.myapp.com --only runtime
```

Dynamic scanning runs regardless of `--mode`. Even `--mode quick` (which skips the heavier
*static* detectors) still performs the full `--url` probe — so quick mode plus `--url` is a
fast "is the live site OK?" check.

> **Use a staging or test environment, not production, where you can.** The probes are
> safe and idempotent (more on that below), but you generally don't want noise — or a
> handful of 404s and a triggered error page — in your production logs.

---

## What it actually checks

When you give it a `--url`, NjordScan makes a small number of benign requests and looks
for things that are visible only at runtime:

| Check | What it means in plain English |
|-------|-------------------------------|
| **Live security headers** | Reads the *real* headers your server sends and flags missing protections: `Content-Security-Policy` (your main safety net against injected scripts), `Strict-Transport-Security`/HSTS (forces HTTPS), `X-Frame-Options` or CSP `frame-ancestors` (stops clickjacking), `X-Content-Type-Options: nosniff`, and `Referrer-Policy`. It also notes when a `Server`/`X-Powered-By` header **leaks a version number** that helps attackers. |
| **Insecure cookie flags** | Inspects `Set-Cookie` headers on the live response and flags cookies missing `HttpOnly`, `Secure`, or `SameSite` — the flags that keep cookies away from scripts and off insecure connections. |
| **Reflected XSS** | Adds a harmless, distinctive marker to a URL parameter and checks whether it comes back **unescaped** inside the HTML. If it does, the page is echoing user input without sanitizing it — the classic ingredient for a cross-site scripting bug. |
| **Open redirect** | Tries common redirect parameters (`next`, `url`, `redirect`, `return`, and similar) pointing at an off-site address, and checks whether the server actually redirects there. Open redirects get abused for convincing phishing links. The "external" target is an **invalid, unreachable domain**, so nothing is ever really fetched. |
| **Verbose errors** | Requests a deliberately bad path and checks whether the server answers with a **stack trace or internal error detail** (HTTP 5xx with traceback-looking text). Leaked stack traces hand attackers a map of your internals. |
| **Exposed AI endpoints** | Looks at common AI/LLM routes (`/api/chat`, `/api/ai`, `/api/generate`, …) and flags any that answer with an **API-shaped response (JSON/SSE) without requiring login**. An open AI endpoint is a "denial-of-wallet" risk — strangers can run up your model bill. It only *checks whether they answer*; see the safety note below. |

Each finding comes with the same plain-English "Why this matters" and "How to fix it"
explanation as a static finding. You can also dig into any rule on its own:

```bash
njordscan explain headers.missing-csp
njordscan explain dast.reflected-xss
```

The dynamic rule IDs are things like `headers.missing-csp`, `headers.missing-hsts`,
`headers.missing-x-frame-options`, `cookie.insecure-flags-live`, `dast.reflected-xss`,
`dast.open-redirect`, `dast.verbose-error`, and `ai-endpoint.unauthenticated-live`. The
full list — with severities — lives in the [rules catalog](RULES.md).

---

## Built to be safe to point at things

A security tool you aim at a live server has to behave itself. NjordScan's dynamic scanner
is deliberately conservative:

- **TLS verification stays ON.** It never disables certificate checking. If a site has a
  broken or self-signed certificate, the request simply fails — it won't silently scan
  over an untrusted connection.

- **It refuses private and loopback hosts by default.** If you point it at something like
  `localhost`, `127.0.0.1`, `192.168.x.x`, `10.x.x.x`, or any other private/link-local
  address, it declines and tells you why:

  ```
  runtime: refusing to scan private/loopback host localhost (use --allow-private)
  ```

  This is an **SSRF guardrail** (Server-Side Request Forgery): it stops the tool from being
  turned into something that quietly probes your internal network. It resolves the
  hostname's actual IP before deciding, so a public name that points at a private address
  is caught too. To deliberately scan a private host, you opt in with `--allow-private`
  (see the next section).

- **Probes are benign and idempotent.** It only makes safe `GET` requests. It never sends
  real attack payloads that could change data or state, the open-redirect "target" is an
  **invalid domain that is never actually fetched**, and the reflected-XSS marker is a
  harmless string, not working exploit code.

- **It never spends your money.** For AI endpoints it only does a read-only check of
  whether the route answers without auth — it **never POSTs** a prompt to an AI/LLM
  endpoint, so it can't trigger a paid model call.

- **It never crashes your scan.** If the host is unreachable, slow, or behaves oddly, the
  dynamic part degrades to "no findings" and the rest of your scan continues normally.

---

## Scanning localhost during development

While you're building, your app usually runs on `http://localhost:3000` — exactly the kind
of private/loopback host the SSRF guardrail blocks. When you *intend* to scan your own dev
server, opt in with `--allow-private`:

```bash
# in one terminal: npm run dev   (your app on http://localhost:3000)

# in another:
njordscan scan . --url http://localhost:3000 --allow-private
```

`--allow-private` is the **only** thing that lets `--url` reach a private or loopback
address. Use it on purpose, for hosts you own — not as a habit, and never to scan
addresses you don't control.

---

## Static vs dynamic: when to use which

They answer different questions, and they're best together.

| | **Static** (default) | **Dynamic** (`--url`) |
|---|---|---|
| Looks at | Your **code & config** | A **running app's responses** |
| Needs a server running? | No | Yes |
| Catches | Hardcoded secrets, vulnerable dependencies, dangerous code patterns, risky config | Real headers, live cookie flags, reflected XSS, open redirects, leaked errors, exposed AI routes |
| Good for | Every commit, every PR, CI on every push | Staging checks, pre-release, "is the deployed app configured right?" |

**Rules of thumb:**

- Run **static** scanning constantly — it's the default, it's fast, and it needs nothing
  running. It's your everyday safety net (great in CI; see the [CI/CD guide](ci-cd.md)).
- Add **dynamic** scanning when you have a **deployed, reachable app** to point at —
  typically against staging before a release, or against `localhost` while you're working
  on headers, cookies, or auth.
- The two **complement** each other. Static analysis can warn that a *config* looks wrong;
  dynamic scanning confirms what the server *actually sends* to a browser. Use both and you
  cover both "what the code says" and "what the app does."

---

## Honest about the limits

Dynamic scanning here is intentionally a **lightweight, safe DAST** — a fast, friendly
sanity check, **not** a full penetration test. Worth knowing:

- It runs a **fixed set of benign, surface-level probes**. It does not crawl your whole
  site, log in, fill out forms, or chain requests together the way a human tester (or a
  heavyweight DAST suite) would.
- It checks the **URL you give it** (and a few well-known paths on that origin). It won't
  discover every page or API route on its own.
- Because it only sends safe, idempotent requests, it **won't find bugs that require
  actually attacking the app** — things like SQL injection, authentication bypasses, or
  complex business-logic flaws are out of scope by design.
- A clean dynamic report means "**none of these specific checks fired**," not "this app is
  proven secure." For anything high-stakes, treat it as a helpful first pass and still get
  a real security review.

Used the right way — alongside the static scan, on every release — it's a quick, low-effort
way to catch the runtime mistakes that are genuinely easy to miss.

---

## See also

- [Getting started](getting-started.md) — install and run your first scan.
- [CI/CD & PRs](ci-cd.md) — wire NjordScan into your pipeline.
- [AI features](ai-features.md) and [AI assistants (MCP)](ai-assistant-mcp.md).
- [Rules catalog](RULES.md) — every rule, including the dynamic ones, with severities.
- [Project README](../README.md) — the big-picture overview.

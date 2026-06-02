# Security Policy

NjordScan is a security tool, so we hold *its own* security to a high bar. It runs on
developers' machines and in CI, it reads source code, and — when you opt in — it can talk
to a live URL or an external AI provider. A bug in any of those paths matters more than in
an average project, and we treat reports accordingly.

If you've found a way to make NjordScan do something it shouldn't, thank you — please tell
us privately first so we can fix it before it's public.

## Reporting a vulnerability

**Please report security issues privately, not in a public issue.**

The preferred way is GitHub's private vulnerability reporting:

1. Go to the **[Security tab](https://github.com/Nimdy/NjordScan/security)** of the repo.
2. Click **"Report a vulnerability"** to open a private advisory only the maintainers can see.
3. Tell us what you found, how to reproduce it, and what an attacker could do with it.

> **Maintainers:** private reporting must be turned on for that button to appear —
> enable it under **Settings → Code security and analysis → Private vulnerability reporting**.

If private advisories aren't available to you for some reason, contact the maintainer:
**[maintainer — fill in, or direct reporters to GitHub private reporting above]**. Please don't
post details in a public issue or discussion until a fix is out.

A good report usually has:

- the NjordScan version (`njordscan version`) and how you installed it,
- the exact command and, if relevant, a minimal scan target that triggers it,
- what you expected vs. what happened, and the impact.

## What's in scope

Vulnerabilities in the **njordscan tool itself** — anything where scanning, reporting, or the
optional network/AI features can be turned against the person running them. For example:

- **Code or command execution from a scan target.** NjordScan analyzes untrusted code
  statically — it should *read* your project, never *run* it. If a crafted file, filename,
  config (`.njordscan.yml`), lockfile, or `node_modules` layout can get NjordScan to execute
  code, write outside the report path, or escape its analysis, that's in scope.
- **The redaction boundary for AI features.** With `--explain-with-ai` / `--ai-fix` against a
  *hosted* provider, NjordScan redacts secrets from code before sending it. If a real
  credential can slip past redaction to an external provider — without `--no-redact` — that's a
  leak, and it's in scope. (Same for any case where `--no-external` fails to block a network call.)
- **The SSRF guard on `--url` (DAST).** Dynamic scanning refuses private, loopback, link-local,
  and reserved hosts unless you pass `--allow-private`. If you can bypass that guard — e.g. reach
  `127.0.0.1`, `169.254.169.254`, or an internal host without the flag, via a redirect, DNS
  rebinding, or hostname parsing trick — that's in scope.
- **Report-output injection.** A finding that carries attacker-controlled text into an HTML/SARIF
  report in a way that executes or escapes (e.g. XSS in `--format html`).
- **Malicious update feeds.** Tampering with the OSV / KEV / rules-feed data that `njordscan
  update` pulls in a way that leads to code execution or silently disabling detections.
- **Anything that makes the tool exfiltrate data, crash a whole scan, or report a false "clean"**
  on code that should fire — for a security tool, a silent miss is a real bug.

## What's out of scope

- **The deliberately-vulnerable demo targets.** `examples/vulnerable-shop/` and `simulation-lab/`
  are *intentionally* insecure — they exist so NjordScan has something realistic to find and so
  the purple-team range has something to exploit. The bugs in them are the point, not a
  vulnerability in NjordScan. (If NjordScan *fails to flag* one of those bugs, that's a detection
  issue — please open a normal issue, not a security report.)
- **Missing detections / false negatives in general.** No scanner catches everything. A rule we
  don't have yet is a feature request or a normal bug, not a security vulnerability — unless the
  miss is caused by something attacker-controlled (see scope above).
- **Findings NjordScan reports about *your* app.** Those are about your code; fix them with the
  guidance in the report. NjordScan finding a real issue isn't a vulnerability in NjordScan.
- **Risks you explicitly opted into.** Sending code to a hosted AI provider after passing
  `--no-redact`, or scanning an internal host after passing `--allow-private`, is working as
  documented.
- **Issues only in third-party dependencies** with no impact on NjordScan — report those upstream.
  (If a dependency issue *is* exploitable through NjordScan, that part is in scope.)

## Supported versions

NjordScan is in **2.0 beta**. We support the current beta line; please reproduce on the latest
release before reporting.

| Version | Supported |
|---------|-----------|
| 2.0.x (beta, current — `2.0.0b1`) | ✅ Yes |
| 1.x and earlier | ❌ No — please upgrade |

## What to expect

NjordScan is a **community open-source project (MIT)**, maintained by volunteers — not a company
with a 24/7 security team. We take these reports seriously and will do our best to:

- **acknowledge** your report within about **5 business days**,
- give you an **initial assessment** (in scope / not, rough severity) within about **10 business days**,
- keep you updated while we work on a fix, and credit you in the advisory if you'd like.

These are good-faith targets, not contractual guarantees. Complex issues take longer; please bear
with us. When a fix ships, we'll publish a GitHub Security Advisory so everyone can update.

## Safe harbor

If you're acting in good faith to find and report a vulnerability — only against your own
installation or the deliberately-vulnerable targets in this repo, without accessing others' data,
degrading the service for others, or running scans against systems you don't own — we welcome your
research and won't pursue action over it. Please give us a reasonable chance to fix things before
going public.

Thanks for helping keep NjordScan trustworthy.

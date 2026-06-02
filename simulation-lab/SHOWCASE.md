# 🧪 Simulation Lab — captured output

These are **real, unedited excerpts** from a single `./run-lab.sh` run (ANSI colour
stripped). Reproduce them yourself with `make demo`.

---

## 1. The precision control — a clean app comes back silent

The most important result in the lab. A well-built app must produce **zero** findings,
or a non-expert can't trust the tool.

```
🛡  NjordScan  ·  nextjs  ·  20 files  ·  0.44s
/lab/targets/05-clean-app
╭──────────────────────────────── ✅ All clear ────────────────────────────────╮
│  No security issues found.                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

## 2. LIVE DAST — a vulnerability *confirmed against the running service*

The scanner container hit `http://api:3002` over the lab network. This finding exists
**only because the app was running** — NjordScan sent a probe and watched the response:

```
╭─  8. 🟠 [HIGH] Reflected input appears unescaped in the response ────────────╮
│  http://api:3002/?njordscan=njq9z<x>"'                                        │
│  CWE-79  ·  A03:2021-Injection  ·  ATT&CK T1059.007  ·  confidence: high      │
│                                                                              │
│  A URL parameter is reflected into the HTML unescaped.                        │
│  💡 Why this matters                                                          │
│  NjordScan sent a harmless marker in the URL and the live app echoed it ...   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

The live API scan produced **11 dynamic findings** that no static scan could know:
`dast.reflected-xss`, `dast.open-redirect`, `dast.verbose-error`,
`cookie.insecure-flags-live`, `cookie.missing-httponly`,
`ai-endpoint.unauthenticated-live`, `headers.missing-csp`,
`headers.missing-x-frame-options`, `headers.missing-x-content-type-options`,
`headers.missing-referrer-policy`, `headers.server-version-disclosure`.

---

## 3. Supply-chain — a malicious dependency caught in `node_modules`

```
│  1. [Initial Access] Malicious code arrives via a dependency                  │
│       node_modules/analytics-color-utils/package.json:1                       │
│       Installed dependency 'analytics-color-utils@1.0.4' has a dangerous       │
│       'postinstall' script: Pipes remote content directly into a              │
│       shell/interpreter.                                                       │
│  2. [Execution] It runs at install time, before your app starts               │
```

The benign dependency and the legitimate `node-gyp` native build in the same tree are
**not** flagged.

---

## 4. Attack-path synthesis — the storefront's kill chains

The static scan of target 01 produced **29 findings → 8 attack paths**, including an
`unauth-exec` chain (score 98: an auth-bypass stub on the same route as a SQL-injection
sink) and a `secret-pivot` chain (score 100). See `reports/01-nextjs.txt`.

---

## 5. Keystone — the commit that *armed* a pre-existing chain

Built and scanned entirely inside the scanner container (`make keystone`):

```
🔑 Keystone  ·  this change completed 1 pre-existing attack path(s)

   1. [Initial Access] No authentication on the entry point   ← the link this change added
   2. [Execution] Attacker-controlled data hits a query/command   planted by Alice on <date>
```

A later "temporarily disable auth" commit (Bob) is named as the keystone that completed
a SQL-injection chain a different author planted earlier — *neither change was a
vulnerability alone*.

---

### Run totals (one `./run-lab.sh`)

| Target | Findings | Notes |
|--------|---------:|-------|
| 01 vulnerable-nextjs (static) | 29 | 8 attack paths |
| 01 + live DAST | 33 | static + runtime |
| 02 vulnerable-api + live DAST | 32 | 11 confirmed live |
| 03 supply-chain | 6 | critical install-script |
| 04 keystone | — | 🔑 chain armed |
| 05 clean-app | **0** | ✅ all clear |

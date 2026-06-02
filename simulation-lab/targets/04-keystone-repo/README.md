# Target 04 — Keystone Commit + Git Hygiene

This target demonstrates NjordScan's **🔑 Keystone** analysis: catching the one
commit that **completes a pre-existing kill chain** — a vulnerability that is
invisible in any single diff because its other links were planted earlier, by
someone else.

Unlike every other file in `simulation-lab/`, this target is **not** a static
directory you point a scanner at. The vulnerability is *temporal* — it only
exists across a sequence of commits by different authors — so it ships as a
script that builds a **self-contained, throwaway git repo** outside the
NjordScan source tree (so it never nests a `.git` in the parent repository).

## Run it

```bash
bash build-history.sh           # builds repo in /tmp/njord-keystone (default)
bash build-history.sh /tmp/foo  # or a directory of your choosing
```

The script:

1. Initializes a fresh git repo and lays down a small Next.js storefront.
2. Creates a **3-commit history by three different authors**.
3. Runs `njordscan scan <repo> --diff HEAD~1` and prints the 🔑 Keystone block,
   then the same verdict in JSON (`keystone_paths`).

## The kill chain across the three commits

| # | Author | Commit | What it does | Role in the chain |
|---|--------|--------|--------------|-------------------|
| 1 | **Alice Nguyen** | `feat(api): add product catalog search route` | Adds `GET /api/products?q=...` that interpolates `searchParams` into `db.query(...)` — a SQLi sink. The route is **auth-gated**, so it's not exploitable yet. Also carelessly commits a real `.env`. | **Pre-existing link** (the latent SQLi sink) + a git-hygiene finding |
| 2 | **Carol Diaz** | `feat(lib): add fixed-window rate limiter` | Unrelated helper. Touches nothing on the vulnerable route. | Noise — proves Keystone does **not** blame an innocent change |
| 3 | **Bob Carter** | `chore(api): temporarily disable auth on product search for staging` | Stubs the guard to `const isAuthenticated = (req) => true;`. No injection, no DB call in *his* diff. | **🔑 Keystone** — supplies the missing no-auth link that arms Alice's SQLi |

Bob's one-line diff would sail through PR review. But NjordScan reconstructs the
tree *before* his commit, re-runs the exact same deterministic attack-path
synthesis, and reports the **set-difference**: a chain that exists AFTER but not
BEFORE, with one in-diff link (Bob's) and pre-existing links dated by `git blame`
to Alice.

## What the scan shows

`njordscan scan <repo> --diff HEAD~1` prints:

```
🔑 Keystone  ·  this change completed 1 pre-existing attack path(s)

╭─  Account/data takeover via unauthenticated injection  ──────────────────────╮
│  🔴 score 98 · critical   armed by this change                               │
│  Impact: Unauthenticated read/write of your application data                 │
│                                                                              │
│  ★ 1. [Initial Access] No authentication on the entry point  ← the link      │
│       app/api/products/route.js:6           this change added                │
│    2. [Execution] Attacker-controlled data hits a query/command              │
│       app/api/products/route.js:17          planted by Alice Nguyen on 2026-02-03
│    3. [Impact] Data is read, modified, or destroyed                          │
│       app/api/products/route.js:17          planted by Alice Nguyen on 2026-02-03
│                                                                              │
│  🔑 Step 1 is new in this change; the rest was already in the repo (planted  │
│  by Alice Nguyen). Neither change was a vulnerability alone — together       │
│  they're a complete chain. Revert or guard the new link to disarm it.        │
╰──────────────────────────────────────────────────────────────────────────────╯
```

A full (non-diff) scan of the built repo emits these `rule_id`s:

| rule_id | source | meaning |
|---------|--------|---------|
| `auth.middleware-bypass` | Bob's commit | auth guard hard-wired to `true` (the keystone link) |
| `sqli.tainted-query` | Alice's commit | `searchParams` taint-flows into `db.query` (the pre-existing sink) |
| `hardening.env-committed` | Alice's commit | `.env` is tracked by git (**git hygiene**) |
| `secret.generic` | Alice's `.env` | a live-looking secret inside the committed `.env` |
| `config.missing-security-headers` | app config | no security headers configured |
| `supply-chain.missing-lockfile` | repo | no lockfile committed |

And two attack paths: `unauth-exec` (the keystone chain, score 98) and
`secret-pivot` (server access → harvested `.env` secret, score 100).

## Files

- `build-history.sh` — builds the throwaway repo and runs the keystone scan.
- `print_keystone.py` — pretty-prints `keystone_paths` from the JSON report
  (called by the script for the machine-readable view).

> Note: this is a **script**, not a runnable web app. `start_cmd` is
> `bash build-history.sh`. There are no live HTTP routes to DAST here — the
> demonstration is entirely in the git history + static/keystone analysis.

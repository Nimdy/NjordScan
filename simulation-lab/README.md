# 🧪 NjordScan Simulation Lab

A self-contained **cyber range** for NjordScan — a Docker environment of deliberately
broken targets that you can scan *statically* and, more impressively, **dynamically
over the container network** while the vulnerable services are live.

It exists for two reasons:

1. **Proof.** Every headline capability — attack-path synthesis, the data-egress
   tracer, supply-chain detection, Keystone (the commit that armed a chain), and live
   DAST — is demonstrated against a real target, end to end, in one command.
2. **A real test bed.** It's how we validate the scanner against running services and
   realistic project trees, not just unit fixtures. The same harness doubles as a
   training range or a CI security-gate rehearsal.

```bash
cd simulation-lab
make demo          # build everything, run every scan, capture ./reports/
# or: ./run-lab.sh
make down          # tear it all down
```

Nothing here touches the internet. Every target is intentionally vulnerable; the
"clean" target is intentionally *not* — it's the precision control.

---

## The flex: a scanner that walks a live fleet over the network

The interesting part isn't the broken apps — it's the **topology**. Two vulnerable
services run on an isolated bridge network. A **NjordScan container joins the same
network** and scans them two ways at once:

```
            ┌───────────────────────── labnet (bridge) ─────────────────────────┐
            │                                                                    │
   ┌────────▼────────┐      ┌─────────────────┐                      ┌───────────▼──────────┐
   │  lab-web :3001  │      │  lab-api :3002  │   ◀── live DAST ───  │   lab-scanner        │
   │ vulnerable Next │      │ vulnerable API  │                      │  (njordscan:lab)     │
   └─────────────────┘      └─────────────────┘   ── static scan ─▶  │  mounts /lab source  │
                                                                     └──────────────────────┘
```

```bash
# the scanner hits the RUNNING service by its network name and confirms vulns live:
docker compose run --rm njordscan \
  scan /lab/targets/02-vulnerable-api --url http://api:3002 --allow-private
```

That `--url` scan is real **DAST**: NjordScan sends a harmless marker, watches the live
app echo it back unescaped, and reports a *confirmed* reflected-XSS — alongside the
static findings from the same source. This "containerized scanner walks a live target
mesh and verifies findings against ground truth" pattern generalizes far beyond this
tool: CI security gates, red-team ranges, training labs, any *scan-a-running-fleet*
product.

---

## The targets (what each one proves)

| # | Target | Proves | Captured result |
|---|--------|--------|-----------------|
| **01** | `vulnerable-nextjs` — a full storefront | Static breadth: secrets, SQLi-by-taint, injection, XSS, **data-egress**, weak crypto; **attack-path synthesis** | **29 findings, 8 attack paths** (incl. `unauth-exec` 98, `secret-pivot` 100, `data-egress`) |
| **02** | `vulnerable-api` — a JSON/AI API | **Live DAST** + AI-app risks: reflected XSS, open redirect, insecure cookies, missing headers, **unauthenticated AI endpoint** | **11 live/dynamic findings** confirmed against the running service + static issues |
| **03** | `supply-chain-attack` | A malicious `postinstall` in `node_modules`, a tampered lockfile, a known-vuln pin | `supply-chain.dependency-install-script` (critical) + `missing-integrity` + `deps.known-vulnerability` — benign/native deps **not** flagged |
| **04** | `keystone-repo` (a git history) | **Keystone**: a later "temporarily disable auth" commit by *Bob* completes a SQLi *Alice* planted earlier | The 🔑 Keystone block naming the arming commit + the pre-existing author |
| **05** | `clean-app` | **Precision** — the credibility anchor: a secure app must score **zero** | **0 findings · ✅ All clear** |

The clean app is the most important target. Anyone can make a scanner that screams; the
proof that NjordScan is usable for non-experts is that a well-built app comes back
**silent**.

---

## Layout

```
simulation-lab/
├── docker-compose.yml      # the lab: 2 target services + the scanner, on one network
├── run-lab.sh / Makefile   # one-command demo + per-step targets
├── njordscan/Dockerfile    # the scanner image (installs njordscan[dynamic] + git)
├── targets/
│   ├── 01-vulnerable-nextjs/   (runnable · port 3001 · static + DAST)
│   ├── 02-vulnerable-api/      (runnable · port 3002 · the live DAST target)
│   ├── 03-supply-chain-attack/ (static · malicious node_modules + lockfile)
│   ├── 04-keystone-repo/       (build-history.sh → throwaway git repo)
│   └── 05-clean-app/           (the zero-findings precision control)
└── reports/                # generated scan output (gitignored)
```

## Useful commands

```bash
make build        # build scanner + target images
make up           # start the targets  (web → :3001, api → :3002)
make scan         # static scans of every target via the containerized scanner
make dast         # LIVE DAST against the running services over the lab network
make keystone     # the temporal "armed a pre-existing chain" demo
make down         # stop everything
```

> Note: DAST against the lab's private container IPs needs `--allow-private` (NjordScan
> refuses private/loopback hosts by default, an anti-SSRF guard). `run-lab.sh` passes it.

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

## 🟣 Purple team: NjordScan predicts → red team proves → blue team detects

The lab isn't just a NjordScan demo — it's a usable **purple-team range**. Two more
containers join the network and close the loop:

```bash
make purple        # the full loop: attack the live targets, then show what defenders saw
make redteam       # just the offensive playbook
make blueteam      # just the detection pass over the access logs
```

- **🔴 Red team** (`redteam/`) — an attacker container that runs a real exploit playbook
  against the *live* services over the network (env-overridable `WEB_URL`/`API_URL`), each
  step mapped to a MITRE ATT&CK technique and verified with captured evidence. A real run:

  > 7/7 techniques landed — recon (T1595.002), reflected XSS (T1059.007), open redirect
  > (T1566.002), **OS command injection → RCE** (`uid=0(root)`, T1059.004), insecure session
  > cookie (T1539), **denial-of-wallet** on the unauthenticated AI endpoint (10/10 calls
  > answered, T1499.003), and verbose-error/secret leak (T1592). Exit code = range smoke test.

- **🔵 Blue team** (`blueteam/`) — a dependency-free Python mini-SIEM that tails the JSON
  access logs the targets write (the `LOG_CONTRACT`) and raises MITRE-mapped alerts. Same run:

  > 38 alerts over 55 events — **CRITICAL os-command-injection** (the RCE, caught on both
  > `;id` and `$(whoami)`), HIGH reflected-xss + denial-of-wallet-burst ("6 requests to
  > /api/chat within 10s"), MEDIUM open-redirect + scanner-tooling-UA, LOW verbose-error —
  > while staying **silent on benign traffic** (normal `GET /`, real searches, internal
  > redirects, low-volume API use).

The vulnerable targets each append one JSON line per request to a shared `/logs` volume,
so the *exact same traffic* the red team generates is what the blue team detects — and
what NjordScan predicted statically in the first place. Red teamers get a live practice
target with a real toolkit; blue teamers get attack telemetry to write and tune detections
against; and the whole thing validates the scanner's predictions against ground truth.

### 🧭 Lateral movement: a segmented internal tier you have to *pivot* to

The range isn't flat. A third tier — the internal **BackOffice** service, which holds the
customer datastore — lives on a **separate, internal-only Docker network** with no
published port and **no route from the attacker container**. The web tier straddles both
networks; the red-team box does not.

```
   labnet (DMZ)                                   internal-net  (internal: true)
   ┌───────────┐   ┌───────────┐                  ┌───────────────────────────┐
   │  lab-web   │──│  lab-api   │                  │       lab-internal        │
   │ (has RCE)  │   └───────────┘                  │ BackOffice — customer DB  │
   └─────┬──────┘ \________ also joins ___________▶└─────────────▲─────────────┘
         │                  internal-net                         │  (web only)
   ┌─────┴──────┐                                                 ✗
   │ lab-redteam│   ✗ no route to lab-internal — must pivot through the web tier
   └────────────┘
```

So the attacker can't touch the crown jewels directly. The red-team playbook proves it the
honest way (**technique 8**):

1. **Direct hit fails** — `curl http://internal:9000/admin/customers` from the attacker box
   has no route. The segmentation holds.
2. **Foothold → discovery** — it reuses the web RCE (technique 4) to run `printenv` and loot
   the shared internal token the web tier carries (`T1552.001`).
3. **Pivot → exfil** — it calls the internal service *from the web box* with the looted
   token and pulls back the customer PII (`T1210`).

The blue team catches the landing: the internal tier writes the same log contract, and the
app itself only ever calls `/account` there — so **any** hit on `/admin/*` is a DMZ→internal
pivot, raised CRITICAL (`internal-tier-access`, T1210). And NjordScan predicted the
ingredients statically — a scan of the web tier flags both the **RCE** and the **hard-coded
internal token** the pivot turns into lateral movement.

```bash
make pivot         # the focused lateral-movement demo (red proves it, blue detects it)
```

---

## The targets (what each one proves)

| # | Target | Proves | Captured result |
|---|--------|--------|-----------------|
| **01** | `vulnerable-nextjs` — a full storefront | Static breadth: secrets, SQLi-by-taint, injection, XSS, **data-egress**, weak crypto; **attack-path synthesis** | **29 findings, 8 attack paths** (incl. `unauth-exec` 98, `secret-pivot` 100, `data-egress`) |
| **02** | `vulnerable-api` — a JSON/AI API | **Live DAST** + AI-app risks: reflected XSS, open redirect, insecure cookies, missing headers, **unauthenticated AI endpoint** | **11 live/dynamic findings** confirmed against the running service + static issues |
| **03** | `supply-chain-attack` | A malicious `postinstall` in `node_modules`, a tampered lockfile, a known-vuln pin | `supply-chain.dependency-install-script` (critical) + `missing-integrity` + `deps.known-vulnerability` — benign/native deps **not** flagged |
| **04** | `keystone-repo` (a git history) | **Keystone**: a later "temporarily disable auth" commit by *Bob* completes a SQLi *Alice* planted earlier | The 🔑 Keystone block naming the arming commit + the pre-existing author |
| **05** | `clean-app` | **Precision** — the credibility anchor: a secure app must score **zero** | **0 findings · ✅ All clear** |
| **06** | `internal-admin` — the segmented BackOffice tier | **Lateral movement**: no route from the attacker; only a pivot through the web RCE reaches the customer datastore | Direct hit blocked; the web RCE pivots in and exfiltrates PII; blue raises CRITICAL `internal-tier-access` |

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
│   ├── 05-clean-app/           (the zero-findings precision control)
│   └── 06-internal-admin/      (segmented · internal-net only · the pivot target)
└── reports/                # generated scan output (gitignored)
```

## Useful commands

```bash
make build        # build scanner + target images
make up           # start the targets  (web → :3001, api → :3002, internal → segmented)
make scan         # static scans of every target via the containerized scanner
make dast         # LIVE DAST against the running services over the lab network
make pivot        # lateral-movement demo: pivot through the web RCE to the internal tier
make keystone     # the temporal "armed a pre-existing chain" demo
make down         # stop everything
```

> Note: DAST against the lab's private container IPs needs `--allow-private` (NjordScan
> refuses private/loopback hosts by default, an anti-SSRF guard). `run-lab.sh` passes it.

## Demo secrets: arm / disarm (so the repo stays pushable)

The lab and examples contain "leaked" secrets for NjordScan to find. A *real-format*
provider key (`AKIA…`, `sk_live_…`) is — by design — blocked by GitHub push protection,
which can't tell a fake demo secret from a real leak. So the committed (**disarmed**)
state uses neutralized values that NjordScan **still flags** (via its generic-secret
heuristic, and the secret-pivot attack path still forms) but that no secret scanner
treats as a real provider key — the repo pushes clean, no bypass.

For the full provider-specific demo locally (so the report says *"AWS access key"* /
*"Stripe key"* instead of *"generic secret"*):

```bash
make arm        # inject real-FORMAT fake keys (generated at runtime — DO NOT COMMIT)
make secrets    # show armed/disarmed status
make disarm     # restore the pushable placeholders before you commit
```

Armed files are intentionally **not** gitignored: if you accidentally `git add` one,
GitHub push protection stops you — the safety net working as intended.

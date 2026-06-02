# Red Team — adversary-emulation playbook

The attacker component of the NjordScan simulation lab. It runs **real exploits**
against the two live, intentionally-vulnerable targets over plain HTTP and prints
the proof for each hit (the reflected payload, the `Location` header, the
injected-command output, the stealable `Set-Cookie`, the unauthenticated AI JSON,
and the leaked stack trace). Every technique is mapped to a MITRE ATT&CK ID.

Nothing here is faked: the script sends each payload to the running service and
shows the actual response. It exits `0` only if **every** technique demonstrably
lands, so it doubles as an end-to-end smoke test for the range.

## Targets

| Service | Name (labnet) | Host port | App | Source |
|---------|---------------|-----------|-----|--------|
| `web`   | `web:3001`    | `localhost:3001` | "ShopDash" storefront | `../targets/01-vulnerable-nextjs` |
| `api`   | `api:3002`    | `localhost:3002` | "QuickNotes" JSON/AI API | `../targets/02-vulnerable-api` |

The target base URLs are overridable via env, defaulting to the docker-network
service names:

```sh
WEB_URL   default http://web:3001     # storefront (XSS, redirect, RCE, cookie, stack)
API_URL   default http://api:3002     # JSON/AI API (XSS, redirect, cookie, AI abuse, stack)
```

## Run it

### On the lab network (Docker)

```sh
# 1. bring the targets up (from simulation-lab/)
docker compose up -d web api

# 2. build + run the attacker on the same bridge network
docker build -t njordlab-redteam:local ./redteam
docker run --rm --network njordscan-lab_labnet njordlab-redteam:local
```

The container resolves `web` and `api` by name over `labnet`, so no env override
is needed.

### Against localhost (no Docker)

Start both targets, then point the script at the published ports:

```sh
# from simulation-lab/redteam/
PORT=3001 node ../targets/01-vulnerable-nextjs/server.js &
PORT=3002 node ../targets/02-vulnerable-api/server.js &

WEB_URL=http://localhost:3001 API_URL=http://localhost:3002 ./attack.sh
```

### Container against host ports

```sh
docker run --rm \
  -e WEB_URL=http://host.docker.internal:3001 \
  -e API_URL=http://host.docker.internal:3002 \
  njordlab-redteam:local
```

## Toolset / offline behaviour

The Dockerfile is `FROM alpine` and installs `curl`, `bash`, and `nmap`.
`curl` + `bash` are the hard requirement and the whole playbook runs on them
alone. `nmap` is used only by the recon technique for a port/service sweep; if
the image is built fully offline and the `nmap` package can't be fetched, the
build still succeeds and `attack.sh` automatically falls back to a `curl` banner
grab, printing a one-line note that it's in curl-only recon mode.

## The playbook — techniques & MITRE ATT&CK mapping

| # | Technique | Target(s) | Vector | MITRE ATT&CK | Proof printed |
|---|-----------|-----------|--------|--------------|---------------|
| 1 | Reconnaissance / fingerprinting | web + api | `curl -I` (or `nmap -sV`) | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) — Active Scanning: Vulnerability Scanning | `X-Powered-By` software/version banners |
| 2 | Reflected XSS | web + api | `GET /search?q=<script>…` | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) — JavaScript | raw `<script>` echoed unescaped into the HTML |
| 3 | Open redirect | web + api | `GET /go?url=…`, `GET /?next=…` | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) — Phishing: Spearphishing Link | `Location: https://evil.example/…` |
| 4 | OS command injection → RCE | web | `GET /ping?host=127.0.0.1;id` | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) — Unix Shell | `uid=…(…)` and `njord_pwned_<user>` command output |
| 5 | Insecure session cookie | web + api | `GET /login`, `GET /` | [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie | `Set-Cookie` lacking HttpOnly/Secure/SameSite |
| 6 | Unauthenticated AI abuse / denial of wallet | api | `POST /api/chat` ×10 (no auth) | [T1499.003](https://attack.mitre.org/techniques/T1499/003/) — Application Exhaustion Flood | 10/10 HTTP 200 with no credentials + prompt-injection → server-side `eval` |
| 7 | Verbose errors / info disclosure | web + api | `GET /boom`, `GET /<bad-path>` | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) — Gather Victim Host Information: Software | full stack traces + leaked hard-coded secret |

### Why each one matters

1. **Recon** — both services advertise their software and version via
   `X-Powered-By` and set no hardening headers, handing an attacker a free
   inventory of what to attack.
2. **Reflected XSS** — `/search?q=` interpolates the query straight into the
   HTML body. A crafted link runs attacker JavaScript in the victim's session
   (cookie theft, account takeover) — which chains directly into technique 5.
3. **Open redirect** — `/go?url=` (and the API's root `?next=`) honor any
   absolute URL with no allowlist, so a trusted-looking link bounces the victim
   to a phishing/credential-harvesting page.
4. **Command injection** — the web target builds `ping -c 1 <host>` and runs it
   through a shell via `child_process.exec`, so `;id` executes a second command.
   The playbook prints the real `uid=…` line and an `echo njord_pwned_$(whoami)`
   marker, proving arbitrary remote code execution.
5. **Insecure cookie** — the session cookie is set with no `HttpOnly` (so the
   XSS in #2 can read `document.cookie`), no `Secure` (sniffable over plain
   HTTP), and no `SameSite` (sent cross-site). It is stealable and replayable.
6. **Unauthenticated AI abuse / denial of wallet** — `POST /api/chat` has no
   sign-in check and no rate limit, so the playbook fires 10 requests with zero
   credentials and every one is answered. In a real deployment each call bills a
   model provider → denial of wallet. As a bonus it lands a prompt injection
   whose reply contains a `CALC:` line the server `eval()`s — server-side code
   execution driven by model output.
7. **Verbose errors** — the web `/boom` route returns a full stack trace that
   embeds a hard-coded secret (`STRIPE_SECRET_KEY`), and the API returns a raw
   Node stack trace (file paths, line numbers) on any unknown route, leaking
   internal structure to anyone who asks.

## Output & exit code

Each technique prints a header, its MITRE ID, the raw evidence, and a
`[LANDED]` / `[MISS]` verdict, followed by a final scorecard. The script exits
`0` when all techniques land and `1` if any miss (and `2` if a target is
unreachable), making it usable in CI/`make` as a range health check.

## Blue-team view

This playbook is the offensive half of a purple-team exercise. Each request it
sends is logged by the targets to `/logs/web.log` and `/logs/api.log` (one JSON
line per request), and the NjordScan scanner detects the same vulnerability
classes statically and via DAST — so you can line up *attack → log → finding*
for every technique above.

# NjordScan Simulation Lab — Blue-Team Detector (`detect.py`)

A dependency-free **mini-SIEM** for the NjordScan purple-team range. It tails the
JSON access logs that the two vulnerable targets (`web` on `:3001`, `api` on
`:3002`) emit, runs a catalogue of detection rules over every request, and
prints structured **ALERTS** mapped to MITRE ATT&CK techniques.

- **Pure Python 3 standard library** — no `pip install`, no virtualenv. Runs
  anywhere `python3` exists (tested on 3.12).
- **Two modes:** `--once` (process existing logs and exit — for CI/tests) and
  `--follow` (default; `tail -f`-style live streaming).
- **Tuned for precision:** normal browser traffic does not alert.

---

## Quick start

```bash
# Live tail of the lab's logs (default mode)
python3 detect.py                       # reads $LOG_DIR or /logs
python3 detect.py --follow --log-dir /var/log/njordlab

# One-shot scan of existing logs, then a summary table (CI / smoke test)
python3 detect.py --once --log-dir /tmp/logs

# Inspect the rule catalogue (name, severity, MITRE id, description)
python3 detect.py --list-rules

# Print only the summary, no per-alert lines
python3 detect.py --once --log-dir /tmp/logs --quiet
```

Environment override: `LOG_DIR=/logs python3 detect.py` (the `--log-dir` flag
takes precedence over the env var; the built-in default is `/logs`).

Colour output auto-enables on a TTY. Force it off with `NO_COLOR=1`, on with
`FORCE_COLOR=1`.

---

## How it consumes the log contract

Each vulnerable target appends **one JSON object per line, one per HTTP
request**, to `<LOG_DIR>/<svc>.log` (e.g. `/logs/web.log`, `/logs/api.log`).
The detector reads every `*.log` file in the directory. Schema:

```json
{
  "ts":     "2026-06-01T12:00:03Z",
  "svc":    "web",
  "ip":     "203.0.113.9",
  "method": "GET",
  "path":   "/search",
  "query":  "q=<script>alert(1)</script>",
  "status": 200,
  "ua":     "Mozilla/5.0 ...",
  "ref":    "http://localhost:3001/",
  "body":   ""
}
```

| Field    | Used by the detector for…                                              |
|----------|------------------------------------------------------------------------|
| `ts`     | Burst windowing (event-time, so `--once` over history works correctly) |
| `svc`    | Alert attribution (`svc=web` / `svc=api`)                              |
| `ip`     | Alert attribution + burst grouping key                                |
| `method` | Carried through; informational                                        |
| `path`   | Pattern matching + burst bucket (`/api/chat`, `/login`, generic path) |
| `query`  | Primary injection surface (raw, url-decoded) — XSS/SQLi/cmd/traversal/redirect |
| `status` | `verbose-error` rule (HTTP 500)                                        |
| `ua`     | `scanner-tooling-ua` rule                                             |
| `ref`    | Carried through; informational                                        |
| `body`   | POST injection surface (matched alongside path+query)                 |

Robustness:

- **Any field may be empty.** Missing/empty fields are tolerated.
- **Malformed lines are skipped** (not crashed on) and counted as
  `malformed lines skipped` in the summary.
- Most rules match against `path + query + body` lower-cased, so a payload in a
  POST body is caught the same as one in the query string.
- `--follow` handles **late-created log files**, **truncation** and **rotation**
  (when a file shrinks or its inode changes, it is re-read from the top), and
  **seeks to end on startup** so only new traffic alerts.

---

## Detection rules & MITRE ATT&CK mapping

| Rule | Severity | MITRE ATT&CK | What it catches |
|------|----------|--------------|-----------------|
| `reflected-xss` | HIGH | [T1059.007 – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) | `<script`, `</script`, `%3Cscript`, `onerror=`/`onload=`/… handlers, `javascript:`, `<img src=`, `<svg`, `<iframe`, `document.cookie`, `alert(` |
| `sql-injection` | HIGH | [T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | `UNION SELECT`, `OR 1=1`, `' OR '…'='`, `; DROP TABLE`, `sleep()`, `benchmark()`, `waitfor delay`, `information_schema`, `xp_cmdshell`, `-- ` |
| `os-command-injection` | **CRITICAL** | [T1059.004 – Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/) | `;id`/`;cat`/`;whoami`…, `\| cmd`, `&& cmd`, `$(...)`, `` `...` ``, `%3Bid`, `%7c cmd`, `;sleep N` (esp. against `/ping`) |
| `path-traversal` | HIGH | [T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) | `../`, `..\`, `%2e%2e`, `..%2f`, `%2e%2e%2f`, `..%5c`, repeated `../../`, `/etc/passwd` |
| `open-redirect` | MEDIUM | [T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | `url=`/`next=`/`redirect=`/`return=`/… (incl. `/go?url=`) pointing at an **external** host. Internal/relative targets (`/account`, `localhost`, RFC-1918) are ignored |
| `scanner-tooling-ua` | MEDIUM | [T1595.002 – Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | Offensive-tool User-Agents: `nmap`, `nikto`, `sqlmap`, `njordscan`, `dirb`, `dirbuster`, `gobuster`, `wpscan`, `masscan`, `nuclei`, `hydra`, `wfuzz`, `ffuf`, `zaproxy`, `curl/`, `wget/`, `python-requests` |
| `verbose-error` | LOW | [T1592 – Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/) | HTTP `500` responses — the lab's targets leak stack traces (and a secret) on `/boom` and on injection-triggered errors |
| `denial-of-wallet-burst` | HIGH | [T1499.003 – Endpoint DoS: Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/) | A burst of requests from one IP within a short window. Tuned buckets: **`/api/chat`** (denial-of-wallet against the unauthenticated AI endpoint, >5/10s), **`/login`** (credential brute force, >5/10s), and any single path hammered (>30/10s) |

### Notes on tuning (why benign traffic stays quiet)

- **Open-redirect** only fires when a redirect parameter resolves to an
  *absolute, external* URL. `url=/account` (relative) and
  `url=https://localhost:3001/...` or RFC-1918 hosts (our own services) are
  treated as benign.
- **`/etc/passwd`** is classified as **path-traversal**, not command injection.
  A genuine command-substitution that reads it (`$(cat /etc/passwd)`) still
  fires `os-command-injection` via the `$(...)` pattern, so nothing is lost — it
  is simply not double-counted as a shell exec for a plain file-read.
- **SQL `--` comment** requires a trailing space (`-- `) so it doesn't match
  benign hyphenated input.
- **Command-injection encoded forms** (`%3B`, `%7c`) require a command keyword
  after them, so a bare encoded pipe/semicolon in normal data does not alert.
- **Bursts** use a per-`(ip, bucket)` cool-down: one alert per window, not one
  per request, so a flood produces a single actionable alert.

---

## Alert format

```
[ALERT][HIGH][T1059.007] reflected-xss  svc=web ip=203.0.113.9 path=/search?q=<script>alert(1)</script>  evidence='<script'
       │     │           │              │       │              │                                          └ the exact substring that matched
       │     │           │              │       │              └ path?query (truncated at 80 chars)
       │     │           │              │       └ source IP
       │     │           │              └ which target service
       │     │           └ rule name
       │     └ MITRE ATT&CK technique id
       └ severity (CRITICAL > HIGH > MEDIUM > LOW)
```

`--once` ends with a summary table: counts per rule (with severity + technique)
and a per-severity rollup, plus how many events were parsed and how many
malformed lines were skipped.

---

## Self-validation

A mixed malicious/benign sample and the expected behaviour are exercised by the
shipped check. Write a sample log per the contract and run:

```bash
mkdir -p /tmp/logs
# ... write web.log / api.log with both attacks and normal traffic ...
python3 detect.py --once --log-dir /tmp/logs
```

The detector fires on every attack class (XSS, SQLi, command injection, path
traversal, open redirect, scanner UA, verbose 500, and an `/api/chat` burst) and
stays **silent** on benign traffic: a normal `GET /`, `GET /search?q=laptop`, a
relative `/go?url=/account`, an internal-host redirect, `GET /api/notes`, a
normal `/login` POST, and low-volume legitimate `/api/chat` usage.

---

## Files

- `detect.py` — the detector / mini-SIEM (this is the whole tool).
- `README.md` — this document.

## Where it fits in the lab

```
targets/01-vulnerable-nextjs  ──┐
   (svc "web", :3001)           ├──►  <LOG_DIR>/web.log ─┐
targets/02-vulnerable-api     ──┘                        ├──►  detect.py  ──►  ALERTS + summary
   (svc "api",  :3002)         ─────►  <LOG_DIR>/api.log ─┘
```

Run the red-team scan (`njordscan`) against the targets, point `detect.py` at
the shared log directory, and watch the blue team light up in real time.
```

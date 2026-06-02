#!/usr/bin/env bash
# NjordScan Simulation Lab — one-command demo.
#
# Builds the lab, starts the vulnerable target services, then scans them with a
# containerized NjordScan that joins the same network: static scans of the source
# AND live DAST against the running services. All output is captured to ./reports/.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p reports

DC="docker compose"
say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
scan() { $DC run --rm -T njordscan "$@"; }

say "Building lab images (scanner + 2 vulnerable targets)"
$DC build || { echo "build failed"; exit 1; }

say "Starting the vulnerable targets on the lab network"
$DC up -d web api

say "Waiting for targets to come up"
for s in web api; do
  for _ in $(seq 1 30); do
    h=$(docker inspect -f '{{.State.Health.Status}}' "lab-$s" 2>/dev/null || echo none)
    [ "$h" = "healthy" ] && { echo "  lab-$s healthy"; break; }
    sleep 2
  done
done

# ── static scans (the scanner reads the mounted source) ──────────────────────
say "STATIC scan · 01 vulnerable Next.js storefront"
scan scan /lab/targets/01-vulnerable-nextjs | tee reports/01-nextjs.txt
scan scan /lab/targets/01-vulnerable-nextjs --format json -o /lab/reports/01-nextjs.json >/dev/null

say "STATIC scan · 03 supply-chain attack (malicious postinstall + lockfile tamper)"
scan scan /lab/targets/03-supply-chain-attack | tee reports/03-supply-chain.txt

say "PRECISION proof · 05 clean app (expect ZERO findings)"
scan scan /lab/targets/05-clean-app | tee reports/05-clean.txt

# ── LIVE DAST over the docker network ────────────────────────────────────────
say "LIVE DAST · scanning the running API over the lab network (http://api:3002)"
scan scan /lab/targets/02-vulnerable-api --url http://api:3002 --allow-private | tee reports/02-api-dast.txt
scan scan /lab/targets/02-vulnerable-api --url http://api:3002 --allow-private \
  --format json -o /lab/reports/02-api-dast.json >/dev/null

say "LIVE DAST · scanning the running storefront over the lab network (http://web:3001)"
scan scan /lab/targets/01-vulnerable-nextjs --url http://web:3001 --allow-private | tee reports/01-web-dast.txt

# ── temporal: the Keystone demo (git history) ────────────────────────────────
say "KEYSTONE · a later commit completes a pre-existing kill chain"
$DC run --rm -T --entrypoint bash njordscan /lab/targets/04-keystone-repo/build-history.sh | tee reports/04-keystone.txt

say "Done. Reports in ./reports/.  Tear down with:  docker compose down"

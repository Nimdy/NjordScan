#!/usr/bin/env bash
#
# NjordScan Simulation Lab — one-command launcher.
#
# For people who just want to SEE it work. It checks Docker, picks free ports,
# brings up the targets + the segmented internal tier + the web dashboard, opens
# the dashboard in your browser, and (optionally) runs the full purple demo so the
# dashboard fills with real attack + detection data.
#
#   ./start.sh           # bring the lab up and open the dashboard
#   ./start.sh --demo    # ...and immediately run the red-team/blue-team demo
#   ./start.sh down      # stop and remove everything
#
set -uo pipefail
cd "$(dirname "$0")"

# ── pretty output ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  B=$'\033[1m'; R=$'\033[0m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; C=$'\033[1;36m'
  RD=$'\033[1;31m'; M=$'\033[1;35m'; D=$'\033[2m'
else
  B=""; R=""; G=""; Y=""; C=""; RD=""; M=""; D=""
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s▸%s %s\n' "$C" "$R" "$*"; }
ok()   { printf '%s✓%s %s\n' "$G" "$R" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$R" "$*"; }
die()  { printf '%s✗ %s%s\n' "$RD" "$*" "$R" >&2; exit 1; }

banner() {
  printf '\n%s' "$M"
  cat <<'ART'
  ╔═══════════════════════════════════════════════════════════╗
  ║      🛡️  NjordScan Simulation Lab — Purple Range          ║
  ╚═══════════════════════════════════════════════════════════╝
ART
  printf '%s' "$R"
}

# ── preflight ────────────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is not installed. Install Docker Desktop: https://docs.docker.com/get-docker/"; }

preflight() {
  need docker
  docker info >/dev/null 2>&1 || die "Docker is installed but the daemon isn't running. Start Docker Desktop (or 'sudo systemctl start docker') and re-run."
  docker compose version >/dev/null 2>&1 || die "Need Docker Compose v2 ('docker compose'). Update Docker Desktop, or install the compose plugin."
  ok "Docker is ready ($(docker --version | awk '{print $3}' | tr -d ,))"
}

# ── free-port picker (so 3001/3002/8088 being taken doesn't stop a newcomer) ──
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }; return 1; }
pick_port() {
  local p="$1" n=0
  while port_in_use "$p" && [ "$n" -lt 60 ]; do p=$((p + 1)); n=$((n + 1)); done
  printf '%s' "$p"
}

open_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then (xdg-open "$url" >/dev/null 2>&1 &)
  elif command -v open >/dev/null 2>&1; then (open "$url" >/dev/null 2>&1 &)
  elif command -v wslview >/dev/null 2>&1; then (wslview "$url" >/dev/null 2>&1 &)
  else return 1; fi
}

wait_healthy() {
  local name="$1" i tries=40
  for i in $(seq 1 "$tries"); do
    case "$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null)" in
      healthy) return 0;;
      unhealthy) return 1;;
    esac
    sleep 1.5
  done
  return 1
}

# ── teardown ────────────────────────────────────────────────────────────────
if [ "${1:-}" = "down" ] || [ "${1:-}" = "stop" ]; then
  banner; info "Stopping and removing the lab…"
  docker compose --profile purple --profile scanner down 2>/dev/null
  ok "Lab stopped."
  exit 0
fi

# ── bring it up ──────────────────────────────────────────────────────────────
banner
preflight

export WEB_HOST_PORT; WEB_HOST_PORT="$(pick_port 3001)"
export API_HOST_PORT; API_HOST_PORT="$(pick_port 3002)"
export DASH_HOST_PORT; DASH_HOST_PORT="$(pick_port 8088)"
[ "$WEB_HOST_PORT" = "3001" ] || warn "port 3001 busy → using $WEB_HOST_PORT for web"
[ "$API_HOST_PORT" = "3002" ] || warn "port 3002 busy → using $API_HOST_PORT for api"
[ "$DASH_HOST_PORT" = "8088" ] || warn "port 8088 busy → using $DASH_HOST_PORT for the dashboard"

info "Building images and starting the lab…"
say "${D}  (the first run pulls base images + builds — grab a coffee, a few minutes)${R}"
docker compose up -d --build web api internal dashboard || die "Failed to start the lab. Scroll up for the Docker error."

info "Waiting for services to report healthy…"
wait_healthy lab-web       && ok "web target up"        || warn "web didn't report healthy (it may still work)"
wait_healthy lab-api       && ok "api target up"        || warn "api didn't report healthy"
wait_healthy lab-dashboard && ok "dashboard up"         || warn "dashboard didn't report healthy"

URL="http://localhost:${DASH_HOST_PORT}"
printf '\n%s╭─────────────────────────────────────────────────────────╮%s\n' "$G" "$R"
printf   '%s│%s  📊 Dashboard:  %s%-38s%s%s│%s\n' "$G" "$R" "$B" "$URL" "$R" "$G" "$R"
printf   '%s│%s  🛒 web target: http://localhost:%-24s %s│%s\n' "$G" "$R" "$WEB_HOST_PORT" "$G" "$R"
printf   '%s│%s  🤖 api target: http://localhost:%-24s %s│%s\n' "$G" "$R" "$API_HOST_PORT" "$G" "$R"
printf '%s╰─────────────────────────────────────────────────────────╯%s\n\n' "$G" "$R"

open_browser "$URL" && ok "Opened the dashboard in your browser." || say "${D}Open the dashboard URL above in your browser.${R}"

# ── optional purple demo ─────────────────────────────────────────────────────
run_demo() {
  info "Running the purple demo: NjordScan predicts → red team attacks → blue team detects…"
  docker run --rm -v "$PWD/logs:/x" alpine sh -c 'rm -f /x/*.log /x/redteam.jsonl /x/predict.json' 2>/dev/null || true
  say "${M}1/3 NjordScan predicts the attack paths (static scan)…${R}"
  docker compose run --rm --build njordscan scan /lab/targets/01-vulnerable-nextjs --format json -o /lab/logs/predict.json >/dev/null 2>&1 || warn "predict step skipped"
  say "${RD}2/3 Red team attacks the live targets…${R}"
  docker compose run --rm --build redteam || warn "red-team run had issues"
  say "${C}3/3 Blue team detects it in the logs…${R}"
  docker compose run --rm --build blueteam --once || warn "blue-team run had issues"
  ok "Demo complete — watch the dashboard light up (it refreshes live)."
}

if [ "${1:-}" = "--demo" ] || [ "${1:-}" = "demo" ]; then
  run_demo
elif [ -t 0 ]; then
  printf '%sRun the full purple demo now so the dashboard fills with real data? [Y/n]%s ' "$Y" "$R"
  read -r ans
  case "${ans:-Y}" in [Nn]*) say "${D}Skipped. Run it any time:  ./start.sh --demo   (or  make purple)${R}";; *) run_demo;; esac
else
  say "${D}Tip: run the demo any time with  ./start.sh --demo${R}"
fi

printf '\n%sStop the lab when you are done:%s  ./start.sh down\n' "$B" "$R"

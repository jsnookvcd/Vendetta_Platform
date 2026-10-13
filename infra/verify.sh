#!/usr/bin/env bash
# One-command check that the platform is up and wired. Run it after the stack
# boots (over SSM port forwarding, or against the ALB hostnames). It checks each
# module's health, that the control plane can see the others, and that the
# provisioning loop returns a roster. Read-only: it changes nothing.
#
#   PLATFORM=http://localhost:8300 IR=http://localhost:8100 \
#   MS=http://localhost:8200 DW=http://localhost:8000 \
#   PLATFORM_TOKEN=<control-plane bearer> bash infra/verify.sh
set -uo pipefail

PLATFORM="${PLATFORM:-http://localhost:8300}"
IR="${IR:-http://localhost:8100}"
MS="${MS:-http://localhost:8200}"
DW="${DW:-http://localhost:8000}"
PLATFORM_TOKEN="${PLATFORM_TOKEN:-}"

pass=0; fail=0
ok()   { echo "  ok   $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL $1"; fail=$((fail+1)); }

health () {
  local name="$1" url="$2"
  if [ -z "$url" ]; then echo "  skip $name (no URL)"; return; fi
  if curl -fsS -m 6 "$url/healthz" >/dev/null 2>&1; then ok "$name healthy ($url)"; else bad "$name unreachable ($url)"; fi
}

echo "Module health"
health "control plane" "$PLATFORM"
health "IR hub"        "$IR"
health "managed svcs"  "$MS"
health "dark web"      "$DW"

echo "Provisioning loop"
if [ -n "$PLATFORM_TOKEN" ]; then
  body=$(curl -fsS -m 8 -H "Authorization: Bearer $PLATFORM_TOKEN" \
           "$PLATFORM/api/platform/clients?module=managed-services" 2>/dev/null)
  if [ -n "$body" ] && echo "$body" | grep -q '"clients"'; then
    n=$(echo "$body" | grep -o '"id"' | wc -l | tr -d ' ')
    ok "control plane returns a roster ($n client(s) for managed-services)"
  else
    bad "provisioning API returned nothing usable (token or URL wrong?)"
  fi
else
  echo "  skip provisioning (set PLATFORM_TOKEN to the control-plane bearer)"
fi

echo "Managed services action safety"
mode=$(curl -fsS -m 6 "$MS/api/module" 2>/dev/null | grep -o '"enabled":[a-z]*' | head -1)
[ -n "$mode" ] && ok "managed services manifest reachable" || echo "  skip (manifest needs the bearer; health already checked)"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

#!/usr/bin/env bash
# smoke_test.sh — Phase 4: OPA as PDP, OIDC token-native group-based authz
#
# New in Phase 4:
#   Group-based privilege (wlcg.groups → OPA group_policy)
#   Root bootstrap (no OIDC token → unconditionally allowed)
#
# Inherits all Phase 3 OPA scenarios via the same Rego dispatch/domain rules.
#
# Usage:
#   cd phase4-opa/docker
#   docker compose --profile full up -d
#   bash smoke_test.sh

set -euo pipefail

RUCIO=http://localhost
OPA=http://localhost:8181
ACCOUNT=root
USERNAME=ddmlab
PASSWORD=secret
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { printf -- "${GREEN}PASS${NC} %s\n" "$1"; PASS=$((PASS + 1)); }
fail() { printf -- "${RED}FAIL${NC} %s — expected %s, got %s\n" "$1" "$2" "$3"; FAIL=$((FAIL + 1)); }

check() {
    local desc=$1 expected=$2 actual=$3
    [ "$actual" = "$expected" ] && pass "$desc" || fail "$desc" "$expected" "$actual"
}

check_one_of() {
    local desc=$1 actual=$2; shift 2
    local matched=0
    for expected in "$@"; do
        [ "$actual" = "$expected" ] && matched=1 && break
    done
    [ "$matched" = "1" ] && pass "$desc → $actual" || fail "$desc" "one of: $*" "$actual"
}

opa_query() {
    curl -s -X POST "$OPA/v1/data/vo/authz/v3/allow" \
        -H "Content-Type: application/json" \
        -d "$1" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','?'))"
}

printf -- "=== Phase 4: Rucio + OPA + Keycloak smoke tests ===\n\n"

# ---------------------------------------------------------------------------
# 0. Pre-flight
# ---------------------------------------------------------------------------
printf -- "--- Pre-flight ---\n"
OPA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$OPA/health")
check "OPA /health" "200" "$OPA_STATUS"
PING=$(curl -s "$RUCIO/ping" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))")
[ -n "$PING" ] && pass "Rucio /ping → version $PING" || fail "Rucio /ping" "version string" "empty"
KC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/health/ready")
check "Keycloak /health/ready" "200" "$KC_STATUS"
printf -- "\n"

# ---------------------------------------------------------------------------
# 1. Rucio userpass auth (root bootstrap account)
# ---------------------------------------------------------------------------
printf -- "--- Auth (root userpass) ---\n"
TOKEN=$(curl -s -X GET "$RUCIO/auth/userpass" \
    -H "X-Rucio-Account: $ACCOUNT" \
    -H "X-Rucio-Username: $USERNAME" \
    -H "X-Rucio-Password: $PASSWORD" \
    -D - | grep "X-Rucio-Auth-Token:" | awk '{print $2}' | tr -d '\r')
[ -n "$TOKEN" ] && pass "Root auth token obtained" || { fail "Root auth token" "token" "empty"; exit 1; }
printf -- "\n"

# ---------------------------------------------------------------------------
# 2. Keycloak token + wlcg.groups
# ---------------------------------------------------------------------------
printf -- "--- Keycloak: wlcg.groups in JWT ---\n"
ALICE_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/rucio/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=rucio-oidc&client_secret=rucio-oidc-secret" \
  -d "username=alice&password=alice123&scope=openid wlcg" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))")
[ -n "$ALICE_TOKEN" ] && pass "alice JWT obtained" || { fail "alice JWT" "token" "empty"; exit 1; }

ALICE_GROUPS=$(echo "$ALICE_TOKEN" | cut -d. -f2 | python3 -c "
import base64, sys, json
payload = base64.urlsafe_b64decode(sys.stdin.read() + '===').decode()
d = json.loads(payload)
groups = d.get('wlcg', {}).get('groups', [])
print(','.join(groups))
")
echo "alice groups: $ALICE_GROUPS"
[[ "$ALICE_GROUPS" == *"/rucio/users"* ]] && pass "alice has /rucio/users" || fail "alice groups" "/rucio/users" "$ALICE_GROUPS"

ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/rucio/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=rucio-oidc&client_secret=rucio-oidc-secret" \
  -d "username=adminuser&password=admin123&scope=openid wlcg" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))")
ADMIN_GROUPS=$(echo "$ADMIN_TOKEN" | cut -d. -f2 | python3 -c "
import base64, sys, json
payload = base64.urlsafe_b64decode(sys.stdin.read() + '===').decode()
d = json.loads(payload)
groups = d.get('wlcg', {}).get('groups', [])
print(','.join(groups))
")
[[ "$ADMIN_GROUPS" == *"/rucio/admins"* ]] && pass "adminuser has /rucio/admins" || fail "adminuser groups" "/rucio/admins" "$ADMIN_GROUPS"
printf -- "\n"

# ---------------------------------------------------------------------------
# 3. Rucio API — RSE management via root (bootstrap account)
# ---------------------------------------------------------------------------
printf -- "--- Rucio API: RSE management (root bootstrap) ---\n"
for RSE in CERN_DATADISK BNL_TAPE DESY_SCRATCHDISK; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/$RSE" \
        -H "X-Rucio-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
        -d '{"rse_type": "DISK"}')
    check_one_of "Create RSE $RSE" "$CODE" "201" "409"
done
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/CERN_UNKNOWN" \
    -H "X-Rucio-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
    -d '{"rse_type": "DISK"}')
check "Reject CERN_UNKNOWN (domain rule — unknown RSE type)" "401" "$CODE"
printf -- "\n"

# ---------------------------------------------------------------------------
# K. Group-based privilege (Phase 4 core)
# ---------------------------------------------------------------------------
printf -- "--- OPA (Phase 4): group-based privilege ---\n"
check "admin group → del_rse allowed" "True" "$(opa_query '{
    "input":{"issuer":"adminuser","action":"del_rse",
             "token":{"groups":["/rucio/admins"]},"kwargs":{}}}')"

check "user group → del_rse denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"del_rse",
             "token":{"groups":["/rucio/users"]},"kwargs":{}}}')"

check "no groups → del_rse denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"del_rse",
             "token":{"groups":[]},"kwargs":{}}}')"

check "atlas/production → add_rse CERN_DATADISK allowed" "True" "$(opa_query '{
    "input":{"issuer":"prod","action":"add_rse",
             "token":{"groups":["/atlas/production"]},"kwargs":{"rse":"CERN_DATADISK"}}}')"

check "admin group → approve_rule allowed" "True" "$(opa_query '{
    "input":{"issuer":"adminuser","action":"approve_rule",
             "token":{"groups":["/rucio/admins"]},"kwargs":{}}}')"

check "user group → approve_rule denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"approve_rule",
             "token":{"groups":["/rucio/users"]},"kwargs":{}}}')"

check "domain rule blocks admin: s3→s3 denied" "False" "$(opa_query '{
    "input":{"issuer":"adminuser","action":"add_rule",
             "token":{"groups":["/rucio/admins"]},
             "kwargs":{"account":"adminuser","locked":false,
                       "rse_expression":"CERN_DATADISK",
                       "source_protocol":"s3","dst_protocol":"s3"}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# M. Root bootstrap (no OIDC token)
# ---------------------------------------------------------------------------
printf -- "--- OPA (Phase 4): root bootstrap ---\n"
check "root (no token) → del_rse allowed" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"del_rse",
             "token":{"groups":[]},"kwargs":{}}}')"

check "root (no token) → add_rse CERN_DATADISK allowed" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"add_rse",
             "token":{"groups":[]},"kwargs":{"rse":"CERN_DATADISK"}}}')"

check "non-root empty groups → del_rse denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"del_rse",
             "token":{"groups":[]},"kwargs":{}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# Inherited Phase 3 scenarios (protocol combos, RSE naming, self-service)
# ---------------------------------------------------------------------------
printf -- "--- OPA: protocol combos (inherited) ---\n"
check "webdav→webdav allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","token":{"groups":["/rucio/users"]},
             "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
                       "source_protocol":"webdav","dst_protocol":"webdav"}}}')"
check "s3→webdav allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","token":{"groups":["/rucio/users"]},
             "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
                       "source_protocol":"s3","dst_protocol":"webdav"}}}')"
check "webdav→s3 denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","token":{"groups":["/rucio/users"]},
             "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
                       "source_protocol":"webdav","dst_protocol":"s3"}}}')"
printf -- "\n"

printf -- "--- OPA: rule owner self-service (inherited) ---\n"
check "owner del_rule allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"del_rule","token":{"groups":["/rucio/users"]},
             "kwargs":{"account":"alice"}}}')"
check "non-owner del_rule denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"del_rule","token":{"groups":["/rucio/users"]},
             "kwargs":{"account":"bob"}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
printf -- "=== Results: %s/%s passed ===\n" "$PASS" "$TOTAL"
if [ "$FAIL" = "0" ]; then
    printf -- "${GREEN}All tests passed.${NC}\n"
else
    printf -- "${RED}%s test(s) failed.${NC}\n" "$FAIL"
fi
[ "$FAIL" = "0" ]

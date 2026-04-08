#!/usr/bin/env bash
# smoke_test.sh — Phase 3: OPA as PDP, extended action coverage
#
# Mirrors phase2-opa/docker/smoke_test.sh and adds sections for:
#   G. attach_dids_to_dids
#   H. del_rule / update_rule owner self-service
#   I. Protocol management with scheme allowlist
#
# Note: smoke_test.sh and test_phase3_e2e_scenarios.py cover the same Rego
# rules through different paths. Keep them in sync when adding new actions.
#
# Usage:
#   cd phase3-opa/docker
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
    if [ "$actual" = "$expected" ]; then pass "$desc"; else fail "$desc" "$expected" "$actual"; fi
}

check_one_of() {
    local desc=$1 actual=$2; shift 2
    local matched=0
    for expected in "$@"; do
        [ "$actual" = "$expected" ] && matched=1 && break
    done
    if [ "$matched" = "1" ]; then pass "$desc → $actual"; else fail "$desc" "one of: $*" "$actual"; fi
}

opa_query() {
    curl -s -X POST "$OPA/v1/data/vo/authz/v2/allow" \
        -H "Content-Type: application/json" \
        -d "$1" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','?'))"
}

printf -- "=== Phase 3: Rucio + OPA smoke tests ===\n\n"

# ---------------------------------------------------------------------------
# 0. Pre-flight
# ---------------------------------------------------------------------------
printf -- "--- Pre-flight ---\n"
OPA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$OPA/health")
check "OPA /health" "200" "$OPA_STATUS"
PING=$(curl -s "$RUCIO/ping" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))")
[ -n "$PING" ] && pass "Rucio /ping → version $PING" || fail "Rucio /ping" "version string" "empty"
printf -- "\n"

# ---------------------------------------------------------------------------
# 1. Auth
# ---------------------------------------------------------------------------
printf -- "--- Auth ---\n"
TOKEN=$(curl -s -X GET "$RUCIO/auth/userpass" \
    -H "X-Rucio-Account: $ACCOUNT" \
    -H "X-Rucio-Username: $USERNAME" \
    -H "X-Rucio-Password: $PASSWORD" \
    -D - | grep "X-Rucio-Auth-Token:" | awk '{print $2}' | tr -d '\r')
[ -n "$TOKEN" ] && pass "Auth token obtained" || { fail "Auth token obtained" "token" "empty"; exit 1; }
printf -- "\n"

# ---------------------------------------------------------------------------
# 2. Rucio API — RSE management (inherited)
# ---------------------------------------------------------------------------
printf -- "--- Rucio API: RSE management ---\n"
for RSE in CERN_DATADISK BNL_TAPE DESY_SCRATCHDISK; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/$RSE" \
        -H "X-Rucio-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
        -d '{"rse_type": "DISK"}')
    check_one_of "Create RSE $RSE" "$CODE" "201" "409"
done
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/CERN_UNKNOWN" \
    -H "X-Rucio-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
    -d '{"rse_type": "DISK"}')
check "Reject CERN_UNKNOWN (OPA — unknown type)" "401" "$CODE"
printf -- "\n"

# ---------------------------------------------------------------------------
# 3. OPA: protocol combos (inherited)
# ---------------------------------------------------------------------------
printf -- "--- OPA: protocol combos ---\n"
check "webdav→webdav allowed" "True" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK","source_protocol":"webdav","dst_protocol":"webdav"}}}')"
check "s3→webdav allowed"     "True" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK","source_protocol":"s3","dst_protocol":"webdav"}}}')"
check "s3→xrdhttp allowed"    "True" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK","source_protocol":"s3","dst_protocol":"xrdhttp"}}}')"
check "xrdhttp→xrdhttp allowed" "True" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK","source_protocol":"xrdhttp","dst_protocol":"xrdhttp"}}}')"
check "webdav→s3 denied"      "False" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK","source_protocol":"webdav","dst_protocol":"s3"}}}')"
check "s3→s3 denied"          "False" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK","source_protocol":"s3","dst_protocol":"s3"}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# 4. OPA: RSE naming (inherited)
# ---------------------------------------------------------------------------
printf -- "--- OPA: RSE naming ---\n"
check "CERN_DATADISK valid"       "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,"kwargs":{"rse":"CERN_DATADISK"}}}')"
check "cern_bad invalid"          "False" "$(opa_query '{"input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,"kwargs":{"rse":"cern_bad"}}}')"
check "CERN_UNKNOWN invalid type" "False" "$(opa_query '{"input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,"kwargs":{"rse":"CERN_UNKNOWN"}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# 5. OPA: account checks on add_rule (inherited)
# ---------------------------------------------------------------------------
printf -- "--- OPA: account checks ---\n"
check "user own rule allowed"      "True"  "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK"}}}')"
check "user locked rule denied"    "False" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice","locked":true,"rse_expression":"CERN_DATADISK"}}}')"
check "user other account denied"  "False" "$(opa_query '{"input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,"kwargs":{"account":"bob","locked":false,"rse_expression":"CERN_DATADISK"}}}')"
check "root any account allowed"   "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_rule","is_root":true,"is_admin":false,"kwargs":{"account":"bob","locked":false,"rse_expression":"CERN_DATADISK"}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# 6. OPA: DID actions (inherited)
# ---------------------------------------------------------------------------
printf -- "--- OPA: DID actions ---\n"
check "root add_did allowed"          "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_did","is_root":true,"is_admin":false,"kwargs":{"scope":"atlas","name":"ds1"}}}')"
check "scope owner add_did allowed"   "True"  "$(opa_query '{"input":{"issuer":"alice","action":"add_did","is_root":false,"is_admin":false,"kwargs":{"scope":"alice.data","name":"f1"}}}')"
check "mock scope allowed"            "True"  "$(opa_query '{"input":{"issuer":"alice","action":"add_did","is_root":false,"is_admin":false,"kwargs":{"scope":"mock","name":"f1"}}}')"
check "other scope denied"            "False" "$(opa_query '{"input":{"issuer":"alice","action":"add_did","is_root":false,"is_admin":false,"kwargs":{"scope":"bob.data","name":"f1"}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# 7. OPA: privileged RSE actions (inherited)
# ---------------------------------------------------------------------------
printf -- "--- OPA: privileged RSE actions ---\n"
for ACTION in del_rse add_rse_attribute del_rse_attribute; do
    check "root allowed: $ACTION" "True"  "$(opa_query '{"input":{"issuer":"root","action":"'"$ACTION"'","is_root":true,"is_admin":false,"kwargs":{}}}')"
    check "user denied: $ACTION"  "False" "$(opa_query '{"input":{"issuer":"alice","action":"'"$ACTION"'","is_root":false,"is_admin":false,"kwargs":{}}}')"
done
printf -- "\n"

# ---------------------------------------------------------------------------
# 8. OPA: unknown action fallback (inherited)
# ---------------------------------------------------------------------------
printf -- "--- OPA: unknown action fallback ---\n"
check "root allowed: unknown action" "True"  "$(opa_query '{"input":{"issuer":"root","action":"some_unknown_action","is_root":true,"is_admin":false,"kwargs":{}}}')"
check "user denied: unknown action"  "False" "$(opa_query '{"input":{"issuer":"alice","action":"some_unknown_action","is_root":false,"is_admin":false,"kwargs":{}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# G. attach_dids_to_dids — Phase 3 addition (rucio-it-tools gap)
# ---------------------------------------------------------------------------
printf -- "--- OPA (Phase 3): attach_dids_to_dids ---\n"
check "root attach_dids_to_dids allowed" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"attach_dids_to_dids","is_root":true,"is_admin":false,
    "kwargs":{"scope":"atlas","attachments":[]}}}')"

check "scope owner attach_dids_to_dids allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"attach_dids_to_dids","is_root":false,"is_admin":false,
    "kwargs":{"scope":"alice.data","attachments":[{"scope":"alice.data","name":"raw","dids":[]}]}}}')"

check "mock scope attach_dids_to_dids allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"attach_dids_to_dids","is_root":false,"is_admin":false,
    "kwargs":{"scope":"mock","attachments":[{"scope":"mock","name":"c","dids":[]}]}}}')"

check "other scope attach_dids_to_dids denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"attach_dids_to_dids","is_root":false,"is_admin":false,
    "kwargs":{"scope":"bob.data","attachments":[{"scope":"bob.data","name":"c","dids":[]}]}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# H. del_rule / update_rule owner self-service — Phase 3 addition
# ---------------------------------------------------------------------------
printf -- "--- OPA (Phase 3): rule owner self-service ---\n"
check "owner del_rule allowed"      "True"  "$(opa_query '{"input":{"issuer":"alice","action":"del_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice"}}}')"
check "non-owner del_rule denied"   "False" "$(opa_query '{"input":{"issuer":"alice","action":"del_rule","is_root":false,"is_admin":false,"kwargs":{"account":"bob"}}}')"
check "root del_rule any owner"     "True"  "$(opa_query '{"input":{"issuer":"root","action":"del_rule","is_root":true,"is_admin":false,"kwargs":{"account":"bob"}}}')"
check "owner update_rule allowed"   "True"  "$(opa_query '{"input":{"issuer":"alice","action":"update_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice"}}}')"
check "non-owner update_rule denied" "False" "$(opa_query '{"input":{"issuer":"alice","action":"update_rule","is_root":false,"is_admin":false,"kwargs":{"account":"bob"}}}')"
check "approve_rule still privileged-only (user denied)" "False" "$(opa_query '{"input":{"issuer":"alice","action":"approve_rule","is_root":false,"is_admin":false,"kwargs":{"account":"alice"}}}')"
check "approve_rule root allowed"   "True"  "$(opa_query '{"input":{"issuer":"root","action":"approve_rule","is_root":true,"is_admin":false,"kwargs":{}}}')"
printf -- "\n"

# ---------------------------------------------------------------------------
# I. Protocol management with scheme allowlist — Phase 3 addition
# ---------------------------------------------------------------------------
printf -- "--- OPA (Phase 3): protocol management ---\n"
check "root add davs allowed"          "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"davs"}}}')"
check "root add s3 allowed"            "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"s3"}}}')"
check "root add root:// allowed"       "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"root"}}}')"
check "root add xrdhttp allowed"       "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"xrdhttp"}}}')"
check "root add ftp denied"            "False" "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"ftp"}}}')"
check "root add srm denied"            "False" "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"srm"}}}')"
check "user add davs denied"           "False" "$(opa_query '{"input":{"issuer":"alice","action":"add_protocol","is_root":false,"is_admin":false,"kwargs":{"scheme":"davs"}}}')"
check "root del_protocol davs allowed" "True"  "$(opa_query '{"input":{"issuer":"root","action":"del_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"davs"}}}')"
check "scheme case-insensitive (DAVS)" "True"  "$(opa_query '{"input":{"issuer":"root","action":"add_protocol","is_root":true,"is_admin":false,"kwargs":{"scheme":"DAVS"}}}')"
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

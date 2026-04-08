#!/usr/bin/env bash
# smoke_test.sh — end-to-end smoke tests for the Rucio + OPA policy stack
#
# Usage:
#   cd phase2-opa/docker
#   docker compose --profile full up -d
#   bash smoke_test.sh
#
# Requires: curl, awk, python3
# Tests run against http://localhost (Rucio) and http://localhost:8181 (OPA).

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
    if [ "$actual" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc" "$expected" "$actual"
    fi
}

check_one_of() {
    local desc=$1 actual=$2
    shift 2
    local matched=0
    for expected in "$@"; do
        if [ "$actual" = "$expected" ]; then
            matched=1
            break
        fi
    done
    if [ "$matched" = "1" ]; then
        pass "$desc → $actual"
    else
        fail "$desc" "one of: $*" "$actual"
    fi
}

# Query OPA directly and return True/False
opa_query() {
    curl -s -X POST "$OPA/v1/data/vo/authz/allow" \
        -H "Content-Type: application/json" \
        -d "$1" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','?'))"
}

printf -- "=== Rucio + OPA smoke tests ===\n\n"

# ---------------------------------------------------------------------------
# 0. Pre-flight
# ---------------------------------------------------------------------------
printf -- "--- Pre-flight ---\n"

OPA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$OPA/health")
check "OPA /health" "200" "$OPA_STATUS"

PING=$(curl -s "$RUCIO/ping" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))")
if [ -n "$PING" ]; then
    pass "Rucio /ping → version $PING"
else
    fail "Rucio /ping" "version string" "empty"
fi

printf -- "\n"

# ---------------------------------------------------------------------------
# 1. Authentication
# ---------------------------------------------------------------------------
printf -- "--- Auth ---\n"

TOKEN=$(curl -s -X GET "$RUCIO/auth/userpass" \
    -H "X-Rucio-Account: $ACCOUNT" \
    -H "X-Rucio-Username: $USERNAME" \
    -H "X-Rucio-Password: $PASSWORD" \
    -D - | grep "X-Rucio-Auth-Token:" | awk '{print $2}' | tr -d '\r')

if [ -n "$TOKEN" ]; then
    pass "Auth token obtained"
else
    fail "Auth token obtained" "token" "empty"
    exit 1
fi

printf -- "\n"

# ---------------------------------------------------------------------------
# 2. Rucio API — RSE management
# ---------------------------------------------------------------------------
printf -- "--- Rucio API: RSE management ---\n"

for RSE in CERN_DATADISK BNL_TAPE DESY_SCRATCHDISK; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/$RSE" \
        -H "X-Rucio-Auth-Token: $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"rse_type": "DISK"}')
    check_one_of "Create RSE $RSE" "$CODE" "201" "409"
done

for RSE in cern_bad lowercase_rse; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/$RSE" \
        -H "X-Rucio-Auth-Token: $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"rse_type": "DISK"}')
    check "Reject RSE $RSE (schema)" "400" "$CODE"
done

CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/rses/CERN_UNKNOWN" \
    -H "X-Rucio-Auth-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"rse_type": "DISK"}')
check "Reject RSE CERN_UNKNOWN (OPA — unknown type)" "401" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -L "$RUCIO/rses/" \
    -H "X-Rucio-Auth-Token: $TOKEN")
check "List RSEs" "200" "$CODE"

printf -- "\n"

# ---------------------------------------------------------------------------
# 3. Rucio API — Account + Scope management
# ---------------------------------------------------------------------------
printf -- "--- Rucio API: Account + Scope ---\n"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/accounts/testuser" \
    -H "X-Rucio-Auth-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type": "USER", "email": "test@example.com"}')
check_one_of "Create account testuser" "$CODE" "201" "409"

CODE=$(curl -s -o /dev/null -w "%{http_code}" "$RUCIO/accounts/testuser" \
    -H "X-Rucio-Auth-Token: $TOKEN")
check "Get account testuser" "200" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" "$RUCIO/accounts" \
    -H "X-Rucio-Auth-Token: $TOKEN")
check "List accounts" "200" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$RUCIO/accounts/root/scopes/test" \
    -H "X-Rucio-Auth-Token: $TOKEN")
check_one_of "Create scope test" "$CODE" "201" "409"

CODE=$(curl -s -o /dev/null -w "%{http_code}" "$RUCIO/scopes/root/scopes" \
    -H "X-Rucio-Auth-Token: $TOKEN")
check "List scopes for root" "200" "$CODE"

printf -- "\n"

# ---------------------------------------------------------------------------
# 4. OPA policy — Protocol combos (_protocol_combo_allowed)
# ---------------------------------------------------------------------------
printf -- "--- OPA: protocol combos ---\n"

# Allowed: destination WebDAV and XrdHttp can TPC-pull from any source
check "webdav→webdav allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"webdav","dst_protocol":"webdav"}}}')"

check "s3→webdav allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"s3","dst_protocol":"webdav"}}}')"

check "xrdhttp→webdav allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"xrdhttp","dst_protocol":"webdav"}}}')"

check "s3→xrdhttp allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"s3","dst_protocol":"xrdhttp"}}}')"

check "xrdhttp→xrdhttp allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"xrdhttp","dst_protocol":"xrdhttp"}}}')"

# Denied: S3 cannot act as TPC destination — requires FTS streaming
check "webdav→s3 denied (S3 not TPC destination)" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"webdav","dst_protocol":"s3"}}}')"

check "xrdhttp→s3 denied (S3 not TPC destination)" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"xrdhttp","dst_protocol":"s3"}}}')"

check "s3→s3 denied (no TPC)" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"s3","dst_protocol":"s3"}}}')"


check "no protocol hints skips combo check" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK"}}}')"

check "protocol names case-insensitive (S3→WEBDAV)" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK",
    "source_protocol":"S3","dst_protocol":"WEBDAV"}}}')"

printf -- "\n"

# ---------------------------------------------------------------------------
# 5. OPA policy — RSE naming (_rse_name_valid)
# ---------------------------------------------------------------------------
printf -- "--- OPA: RSE naming ---\n"

check "valid RSE name CERN_DATADISK" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,
    "kwargs":{"rse":"CERN_DATADISK"}}}')"

check "valid RSE name BNL_TAPE" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,
    "kwargs":{"rse":"BNL_TAPE"}}}')"

check "invalid RSE name cern_bad (lowercase)" "False" "$(opa_query '{
    "input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,
    "kwargs":{"rse":"cern_bad"}}}')"

check "invalid RSE name CERN_UNKNOWN (bad type)" "False" "$(opa_query '{
    "input":{"issuer":"root","action":"add_rse","is_root":true,"is_admin":false,
    "kwargs":{"rse":"CERN_UNKNOWN"}}}')"

check "RSE expression with operator skips name check" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"site=CERN&type=DATADISK"}}}')"

printf -- "\n"

# ---------------------------------------------------------------------------
# 6. OPA policy — Account checks (_perm_add_rule)
# ---------------------------------------------------------------------------
printf -- "--- OPA: account checks ---\n"

check "user adds rule for own account" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":false,"rse_expression":"CERN_DATADISK"}}}')"

check "user denied: locked rule" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"alice","locked":true,"rse_expression":"CERN_DATADISK"}}}')"

check "user denied: rule for other account" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_rule","is_root":false,"is_admin":false,
    "kwargs":{"account":"bob","locked":false,"rse_expression":"CERN_DATADISK"}}}')"

check "root allowed: rule for any account" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"add_rule","is_root":true,"is_admin":false,
    "kwargs":{"account":"bob","locked":false,"rse_expression":"CERN_DATADISK"}}}')"

check "admin allowed: rule for other account" "True" "$(opa_query '{
    "input":{"issuer":"adminuser","action":"add_rule","is_root":false,"is_admin":true,
    "kwargs":{"account":"bob","locked":false,"rse_expression":"CERN_DATADISK"}}}')"

printf -- "\n"

# ---------------------------------------------------------------------------
# 7. OPA policy — Privileged-only rule actions
# ---------------------------------------------------------------------------
printf -- "--- OPA: privileged-only rule actions ---\n"

for ACTION in del_rule update_rule approve_rule; do
    PAYLOAD_ROOT='{"input":{"issuer":"root","action":"'"$ACTION"'","is_root":true,"is_admin":false,"kwargs":{}}}'
    PAYLOAD_USER='{"input":{"issuer":"alice","action":"'"$ACTION"'","is_root":false,"is_admin":false,"kwargs":{}}}'
    check "root allowed: $ACTION" "True" "$(opa_query "$PAYLOAD_ROOT")"
    check "user denied: $ACTION" "False" "$(opa_query "$PAYLOAD_USER")"
done

printf -- "\n"

# ---------------------------------------------------------------------------
# 8. OPA policy — Privileged-only RSE actions
# ---------------------------------------------------------------------------
printf -- "--- OPA: privileged-only RSE actions ---\n"

for ACTION in del_rse add_rse_attribute del_rse_attribute; do
    PAYLOAD_ROOT='{"input":{"issuer":"root","action":"'"$ACTION"'","is_root":true,"is_admin":false,"kwargs":{}}}'
    PAYLOAD_USER='{"input":{"issuer":"alice","action":"'"$ACTION"'","is_root":false,"is_admin":false,"kwargs":{}}}'
    check "root allowed: $ACTION" "True" "$(opa_query "$PAYLOAD_ROOT")"
    check "user denied: $ACTION" "False" "$(opa_query "$PAYLOAD_USER")"
done

printf -- "\n"

# ---------------------------------------------------------------------------
# 9. OPA policy — update_rse (_perm_update_rse)
# ---------------------------------------------------------------------------
printf -- "--- OPA: update_rse ---\n"

check "root rename to valid name allowed" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"update_rse","is_root":true,"is_admin":false,
    "kwargs":{"parameters":{"rse":"NIKHEF_DATADISK"}}}}')"

check "root rename to invalid name denied" "False" "$(opa_query '{
    "input":{"issuer":"root","action":"update_rse","is_root":true,"is_admin":false,
    "kwargs":{"parameters":{"rse":"nikhef_datadisk"}}}}')"

check "root update without rename allowed" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"update_rse","is_root":true,"is_admin":false,
    "kwargs":{"parameters":{"availability_read":true}}}}')"

check "user denied: update_rse" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"update_rse","is_root":false,"is_admin":false,
    "kwargs":{"parameters":{"rse":"CERN_DATADISK"}}}}')"

printf -- "\n"

# ---------------------------------------------------------------------------
# 10. OPA policy — DID actions (_perm_did_action)
# ---------------------------------------------------------------------------
printf -- "--- OPA: DID actions ---\n"

check "root add_did allowed" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"add_did","is_root":true,"is_admin":false,
    "kwargs":{"scope":"atlas","name":"dataset1"}}}')"

check "scope owner add_did allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_did","is_root":false,"is_admin":false,
    "kwargs":{"scope":"alice.physics","name":"myfile"}}}')"

check "mock scope always allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_did","is_root":false,"is_admin":false,
    "kwargs":{"scope":"mock","name":"testfile"}}}')"

check "other user scope denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"add_did","is_root":false,"is_admin":false,
    "kwargs":{"scope":"bob.private","name":"file"}}}')"

check "scope owner attach_dids allowed" "True" "$(opa_query '{
    "input":{"issuer":"alice","action":"attach_dids","is_root":false,"is_admin":false,
    "kwargs":{"scope":"alice.data","name":"container"}}}')"

check "other scope detach_dids denied" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"detach_dids","is_root":false,"is_admin":false,
    "kwargs":{"scope":"carol.data","name":"container"}}}')"

printf -- "\n"

# ---------------------------------------------------------------------------
# 11. OPA policy — Unknown action fallback
# ---------------------------------------------------------------------------
printf -- "--- OPA: unknown action fallback ---\n"

check "root allowed: unknown action" "True" "$(opa_query '{
    "input":{"issuer":"root","action":"some_unknown_action","is_root":true,"is_admin":false,
    "kwargs":{}}}')"

check "user denied: unknown action" "False" "$(opa_query '{
    "input":{"issuer":"alice","action":"some_unknown_action","is_root":false,"is_admin":false,
    "kwargs":{}}}')"

printf -- "\n"

# ---------------------------------------------------------------------------
# 12. OPA log verification
# ---------------------------------------------------------------------------
printf -- "--- OPA log verification ---\n"

if command -v docker > /dev/null 2>&1 && docker inspect rucio-opa > /dev/null 2>&1; then
    AUTHZ_HITS=$(docker logs rucio-opa 2>&1 | grep -c '"req_path":"/v1/data/vo/authz/allow"' || true)
    if [ "$AUTHZ_HITS" -gt "0" ]; then
        pass "OPA authz/allow endpoint hit ($AUTHZ_HITS requests logged)"
    else
        fail "OPA authz/allow endpoint hit" ">0 requests" "0"
    fi

    POLICY_LOADED=$(docker logs rucio-opa 2>&1 | grep -c '"req_path":"/v1/policies/authz"' || true)
    if [ "$POLICY_LOADED" -gt "0" ]; then
        pass "OPA policy loaded via REST"
    else
        fail "OPA policy loaded" ">0 PUT /v1/policies/authz" "0"
    fi
else
    printf -- "  (skipped — docker not available or rucio-opa not running)\n"
fi

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

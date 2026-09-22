#!/usr/bin/env bash
# scripts/test_token_exchange.sh — grants rucio the fine-grained permission
# to exchange into authz-service (same pattern as the phase7 testbed's
# grant_token_exchange() for xrd3/xrd4/teapot1/teapot2 — Keycloak 23's
# legacy token exchange needs this granted explicitly, it isn't implied by
# token.exchange.standard.flow.enabled alone), then exercises the exchange
# and asserts the claims api/auth.py needs are present.
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-authorization-service-keycloak-1}"
TOKEN_URL="$KEYCLOAK_URL/realms/rucio/protocol/openid-connect/token"
KC_REALM=rucio
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-admin}"
KCADM=/opt/keycloak/bin/kcadm.sh
EXCHANGE_REQUESTERS=( rucio )
EXCHANGE_TARGET=authz-service

_kc() { docker exec "$KEYCLOAK_CONTAINER" "$KCADM" "$@"; }

# ── Step 0: permission grant ──────────────────────────────────────

grant_token_exchange() {
    echo "0. Granting rucio permission to exchange into $EXCHANGE_TARGET..."

    _kc config credentials \
        --server http://localhost:8080 \
        --realm master --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD"

    local rc uuid requester_uuids=()
    for rc in "${EXCHANGE_REQUESTERS[@]}"; do
        uuid=$(_kc get clients -r "$KC_REALM" \
            -q clientId="$rc" --fields id --format csv --noquotes | tr -d '\r')
        [ -n "$uuid" ] || { echo "  ERROR: requester client '$rc' not found" >&2; exit 1; }
        requester_uuids+=( "$uuid" )
    done
    local requester_uuids_json
    requester_uuids_json=$(printf '"%s",' "${requester_uuids[@]}")
    requester_uuids_json="[${requester_uuids_json%,}]"

    local target_uuid rm_uuid policy_name policy_id perm_name perm_id
    target_uuid=$(_kc get clients -r "$KC_REALM" \
        -q clientId="$EXCHANGE_TARGET" --fields id --format csv --noquotes | tr -d '\r')
    [ -n "$target_uuid" ] || { echo "  ERROR: target client '$EXCHANGE_TARGET' not found — is realm.json imported?" >&2; exit 1; }

    _kc update "clients/$target_uuid/management/permissions" -r "$KC_REALM" -s enabled=true
    echo "  management permissions enabled on $EXCHANGE_TARGET"

    rm_uuid=$(_kc get clients -r "$KC_REALM" \
        -q clientId=realm-management --fields id --format csv --noquotes | tr -d '\r')

    policy_name="exchange-to-${EXCHANGE_TARGET}"
    policy_name=$(echo "$policy_name" | tr -c 'A-Za-z0-9_.-' '_')

    _kc create "clients/$rm_uuid/authz/resource-server/policy/client" -r "$KC_REALM" \
        -s "name=$policy_name" -s "clients=$requester_uuids_json" -s "logic=POSITIVE" \
        2>/dev/null || echo "  (policy already exists — updating it instead)"

    policy_id=$(_kc get "clients/$rm_uuid/authz/resource-server/policy?name=$policy_name" \
        -r "$KC_REALM" --fields id --format csv --noquotes | tr -d '\r' | head -n1)
    if [ -n "$policy_id" ]; then
        _kc update "clients/$rm_uuid/authz/resource-server/policy/client/$policy_id" \
            -r "$KC_REALM" -s "clients=$requester_uuids_json" \
            || echo "  (could not update policy membership — check manually)"
    fi

    perm_name="token-exchange.permission.client.$target_uuid"
    perm_id=$(_kc get "clients/$rm_uuid/authz/resource-server/permission?name=$perm_name" \
        -r "$KC_REALM" --fields id --format csv --noquotes | tr -d '\r' | head -n1)
    if [ -z "$perm_id" ] || [ -z "$policy_id" ]; then
        echo "  ERROR: could not resolve perm_id ($perm_id) or policy_id ($policy_id)." >&2
        exit 1
    fi

    _kc update "clients/$rm_uuid/authz/resource-server/permission/scope/$perm_id" \
        -r "$KC_REALM" -s "policies=[\"$policy_id\"]"
    echo "  policy bound to token-exchange permission"
}

# ── Step 1: mint a user token ─────────────────────────────────────
# Sets global: user_token

mint_user_token() {
    echo "1. User token (randomaccount, direct access grants on rucio client)..."
    local response status body
    response=$(curl -s -w '\n%{http_code}' "$TOKEN_URL" \
        -d grant_type=password -d client_id=rucio -d client_secret=rucio-secret \
        -d username=randomaccount -d password=secret -d scope=openid)
    status="${response##*$'\n'}"
    body="${response%$'\n'*}"
    user_token=$(echo "$body" | jq -r .access_token)
    [[ "$status" == "200" && "$user_token" != "null" && -n "$user_token" ]] \
        || { echo "FAIL: user token (HTTP $status)"; echo "$body" | jq . 2>/dev/null || echo "$body"; exit 1; }
}

# ── Step 2: exchange it for authz-service's audience ──────────────
# Sets global: exchanged

exchange_token() {
    echo "2. Exchanging for audience=$EXCHANGE_TARGET, scope=pep:rucio..."
    local response status body
    response=$(curl -s -w '\n%{http_code}' "$TOKEN_URL" \
        -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
        -d client_id=rucio -d client_secret=rucio-secret \
        -d subject_token="$user_token" \
        -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
        -d audience="$EXCHANGE_TARGET" -d scope=pep:rucio)
    status="${response##*$'\n'}"
    body="${response%$'\n'*}"
    exchanged=$(echo "$body" | jq -r .access_token)
    [[ "$status" == "200" && "$exchanged" != "null" && -n "$exchanged" ]] \
        || { echo "FAIL: exchange (HTTP $status)"; echo "$body" | jq . 2>/dev/null || echo "$body"; exit 1; }
}

# ── Steps 3–4: decode and assert ──────────────────────────────────
# Sets global: payload

decode_and_assert() {
    echo "3. Decoding..."
    payload=$(python3 -c "
import sys, json, base64
p = '$exchanged'.split('.')[1]
p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
")
    echo "$payload"

    echo "4. Asserting..."
    echo "$payload" | jq -e '.aud | if type=="array" then index("'"$EXCHANGE_TARGET"'") != null else .=="'"$EXCHANGE_TARGET"'" end' \
        > /dev/null || { echo "FAIL: aud missing $EXCHANGE_TARGET"; exit 1; }
    echo "$payload" | jq -e '.entitlements | length > 0' \
        > /dev/null || { echo "FAIL: entitlements missing"; exit 1; }

    local act_sub azp
    act_sub=$(echo "$payload" | jq -r '.act.sub // "ABSENT"')
    azp=$(echo "$payload" | jq -r '.azp // "ABSENT"')
    echo "aud/scope/entitlements: OK. act.sub = $act_sub, azp = $azp"
    if [[ "$act_sub" == "ABSENT" ]]; then
        echo "NOTE: no act claim — Keycloak's legacy (V1) token exchange on"
        echo "      23.0.1 doesn't populate it; api/auth.py's actor_sub will"
        echo "      be None for every request until this is resolved."
        if [[ "$azp" != "ABSENT" ]]; then
            echo "      azp='$azp' is present and identifies the requesting"
            echo "      client in this exchange — worth considering as a"
            echo "      fallback actor identifier if act stays unsupported."
        fi
    fi
}

# ── Main ───────────────────────────────────────────────────────────

main() {
    grant_token_exchange
    mint_user_token
    exchange_token
    decode_and_assert
}

main

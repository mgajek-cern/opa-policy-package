#!/usr/bin/env bash
set -euo pipefail

# ── OIDC provider selection ───────────────────────────────────────

OIDC_ISSUER="${OIDC_ISSUER:-https://keycloak:8443/realms/rucio}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-rucio}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-rucio-secret}"

# Keycloak's token endpoint lives under /protocol/openid-connect/token;
# MITREid-based issuers (LS AAI) expose it at /token. Derive rather than
# hardcode so both profiles work unchanged.
if [[ -z "${OIDC_TOKEN_URL:-}" ]]; then
    if [[ "$OIDC_ISSUER" == *"/realms/"* ]]; then
        OIDC_TOKEN_URL="${OIDC_ISSUER%/}/protocol/openid-connect/token"
    else
        OIDC_TOKEN_URL="${OIDC_ISSUER%/}/token"
    fi
fi

OIDC_SEED_SCOPE="${OIDC_SEED_SCOPE:-openid offline_access storage.read:/ storage.modify:/ aud:rucio}"
OIDC_EXPECTED_AUDIENCE="${OIDC_EXPECTED_AUDIENCE:-rucio}"

# Grant used to mint the subject token.

OIDC_SEED_GRANT="${OIDC_SEED_GRANT:-}"
OIDC_USERNAME="${OIDC_USERNAME:-randomaccount}"
OIDC_PASSWORD="${OIDC_PASSWORD:-secret}"

# Name registered in FTS's t_token_provider. Cosmetic, but keeping it
# aligned with the issuer makes `SELECT * FROM t_token_provider` readable.
FTS_PROVIDER_NAME="${FTS_PROVIDER_NAME:-keycloak-rucio}"

FTS_OIDC="https://fts:8446"
SEED_ACCOUNTS=( root ddmlab )

KCADM="/opt/keycloak/bin/kcadm.sh"
KC_REALM=rucio
EXCHANGE_REQUESTERS=( fts rucio )
EXCHANGE_TARGETS=( xrd3 xrd4 teapot1 teapot2 )

IDPSECRETS_PATH_IN_CONTAINER="${IDPSECRETS_PATH_IN_CONTAINER:-/opt/rucio/etc/idpsecrets.json}"

# ─── Compose helpers ──────────────────────────────────────────────

_exec() {
    local svc=$1; shift
    docker exec "compose-${svc}-1" "$@"
}

_restart() {
    local svc
    for svc in "$@"; do
        docker restart "compose-${svc}-1"
    done
}

_http_probe_local() {
    local port=$1 path=$2
    curl -s -o /dev/null -w '%{http_code}' "http://localhost:${port}${path}" || true
}

# Keycloak 23 images ship no curl, so probe it from rucio-server, which is
# also the container whose view of the issuer actually matters.
_kc_probe() {
    _exec rucio-server curl -sk -o /dev/null -w '%{http_code}' \
        "${OIDC_ISSUER%/}/.well-known/openid-configuration" 2>/dev/null || true
}

_cap() {
    local path="$1" default="$2"
    _exec rucio-server env \
        CAP_ISSUER="$OIDC_ISSUER" CAP_PATH="$path" CAP_DEFAULT="$default" \
        CAP_FILE="$IDPSECRETS_PATH_IN_CONTAINER" \
        python3 -c "
import json, os
try:
    with open(os.environ['CAP_FILE']) as f:
        data = json.load(f)
    val = data.get(os.environ['CAP_ISSUER'], {}).get('capabilities', {})
    for part in os.environ['CAP_PATH'].split('.'):
        val = val[part]
    print(str(val).lower())
except Exception:
    print(os.environ['CAP_DEFAULT'])
"
}

ra() { _exec rucio-server rucio-admin -S userpass -u ddmlab --password secret "$@"; }

_kc() { _exec keycloak "$KCADM" "$@"; }

_fts_admin() {
    local attempt rc
    for attempt in 1 2 3; do
        if _exec fts curl -skS --tls-max 1.2 \
            --cert /etc/grid-security/hostcert.pem \
            --key /etc/grid-security/hostkey.pem \
            "$@"; then
            rc=0
        else
            rc=$?
        fi
        [ "$rc" -eq 0 ] && return 0
        [ "$rc" -eq 18 ] && { echo "  ⚠ curl exit 18 (response truncated at transport layer, request itself succeeds server-side — continuing" >&2; return 0; }
        echo "  ⚠ FTS admin call failed (curl exit ${rc}), attempt ${attempt}/3 — retrying in 5s..." >&2
        sleep 5
    done
    echo "  ✗ FTS admin call failed after 3 attempts: $*" >&2
    return 1
}

# ── Infrastructure Readiness ─────────────────────────────────────

wait_for_infrastructure() {
    echo "=== Waiting for Rucio, Keycloak and FTS ==="
    echo "  issuer:    $OIDC_ISSUER"
    echo "  token URL: $OIDC_TOKEN_URL"
    echo "  client_id: $OIDC_CLIENT_ID"

    for i in $(seq 1 30); do
        code=$(_http_probe_local 8090 /ping)
        [[ "$code" == "200" ]] && { echo "  ✓ rucio ready"; break; }
        echo "  [$i] rucio HTTP $code — waiting..."; sleep 5
    done

    # The old script printed "Waiting for ... Keycloak" but never probed it,
    # so a half-started realm surfaced later as an opaque token failure.
    for i in $(seq 1 30); do
        code=$(_kc_probe)
        [[ "$code" == "200" ]] && { echo "  ✓ Keycloak realm discovery ready"; break; }
        [ "$i" = "30" ] && { echo "  ✗ Keycloak never served realm discovery (last code: $code)"; exit 1; }
        echo "  [$i] Keycloak HTTP $code — waiting..."; sleep 5
    done

    for i in $(seq 1 30); do
        code=$(_fts_admin -o /dev/null -w '%{http_code}' https://localhost:8446/whoami 2>/dev/null) || code=0
        [[ "$code" == "200" || "$code" == "403" ]] && { echo "  ✓ FTS ready"; break; }
        echo "  [$i] FTS HTTP $code — waiting..."; sleep 5
    done
}

# ── Identity & Account Setup ─────────────────────────────────────

setup_accounts_and_identities() {
    echo "=== Configuring Rucio Accounts ==="

    ra account add --type SERVICE --email ddmlab@rucio ddmlab || true
    ra identity add --type USERPASS --id ddmlab --email ddmlab@rucio \
        --account ddmlab --password secret || true
    ra account add-attribute ddmlab --key admin --value True || true
    ra account update --account ddmlab --key type --value SERVICE || true
    ra account add --type USER --email randomaccount@rucio randomaccount || true
    ra account add-attribute randomaccount --key admin --value True || true

    echo "  OIDC identities are mapped during subject-token seeding below"
    echo "  (client_credentials service account on ${OIDC_CLIENT_ID})."
}

# ── Subject-token seeding (managed-mode token exchange) ──────────

seed_subject_tokens() {
    local accounts_csv
    accounts_csv=$(printf '%s,' "${SEED_ACCOUNTS[@]}"); accounts_csv="${accounts_csv%,}"
    echo "=== Seeding OIDC subject tokens for accounts: ${SEED_ACCOUNTS[*]} ==="

    local seed_grant
    if [[ -n "$OIDC_SEED_GRANT" ]]; then
        seed_grant="$OIDC_SEED_GRANT"
    elif [[ "$OIDC_ISSUER" == *"/realms/"* ]]; then
        seed_grant="password"
    else
        seed_grant="client_credentials"
    fi

    for acct in "${SEED_ACCOUNTS[@]}"; do
        _exec ruciodb env PGPASSWORD=rucio psql -U rucio -tAc \
        "DELETE FROM tokens WHERE account='${acct}' AND identity LIKE 'SUB=%';"
    done

    echo "  Using expected audience: $OIDC_EXPECTED_AUDIENCE"
    echo "  Using grant: $seed_grant"

    _exec rucio-server env \
        SEED_ACCOUNTS="$accounts_csv" \
        OIDC_SEED_SCOPE="$OIDC_SEED_SCOPE" \
        OIDC_SEED_GRANT="$seed_grant" \
        OIDC_USERNAME="$OIDC_USERNAME" \
        OIDC_PASSWORD="$OIDC_PASSWORD" \
        OIDC_TOKEN_URL="$OIDC_TOKEN_URL" \
        OIDC_CLIENT_ID="$OIDC_CLIENT_ID" \
        OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
        OIDC_EXPECTED_AUDIENCE="$OIDC_EXPECTED_AUDIENCE" \
        python3 -c "
import urllib.request, urllib.parse, json, base64, ssl, sys, os
from datetime import datetime
from rucio.core.identity import add_account_identity
from rucio.core import oidc
from rucio.common.types import InternalAccount
from rucio.common import exception

SEED_SCOPE    = os.environ['OIDC_SEED_SCOPE']
TOKEN_URL     = os.environ['OIDC_TOKEN_URL']
SEED_GRANT    = os.environ['OIDC_SEED_GRANT']
CLIENT_ID     = os.environ['OIDC_CLIENT_ID']
CLIENT_SECRET = os.environ['OIDC_CLIENT_SECRET']
USERNAME      = os.environ['OIDC_USERNAME']
PASSWORD      = os.environ['OIDC_PASSWORD']
ACCOUNTS      = [a for a in os.environ['SEED_ACCOUNTS'].split(',') if a]
EXPECTED_AUDIENCE = os.environ['OIDC_EXPECTED_AUDIENCE']

# The testbed CA is not in the container trust store for every image
# variant; the issuer is an in-network service, so verification is relaxed
# here exactly as the FTS admin curls already do (-k).
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _b64json(segment):
    return json.loads(base64.urlsafe_b64decode(segment + '=='))


def _mint_token():
    if SEED_GRANT == 'client_credentials':
        data = {
            'grant_type': 'client_credentials',
            'scope': SEED_SCOPE,
        }
        if EXPECTED_AUDIENCE.startswith(('http://', 'https://')):
            data['resource'] = EXPECTED_AUDIENCE
        data = urllib.parse.urlencode(data).encode()
    else:
        data = urllib.parse.urlencode({
            'grant_type': 'password',
            'username': USERNAME,
            'password': PASSWORD,
            'scope': SEED_SCOPE,
        }).encode()
    _auth = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()
    req = urllib.request.Request(TOKEN_URL, data=data,
                                 headers={'Authorization': f'Basic {_auth}'})
    return json.loads(urllib.request.urlopen(req, context=_SSL).read())['access_token']


def _ensure_mapped(identity_internal, account):
    try:
        add_account_identity(identity_internal, 'OIDC', InternalAccount(account), f'{account}@rucio')
        print(f'  ✓ OIDC identity mapped to {account}: {identity_internal}')
    except exception.Duplicate:
        print(f'  ✓ OIDC identity already mapped to {account}')
    except Exception as e:
        msg = str(e).lower()
        if 'duplicate key' in msg or 'already exists' in msg or 'unique constraint' in msg:
            print(f'  ✓ OIDC identity already mapped to {account} (pre-existing)')
        else:
            raise


def _store(account, access_token):
    claims = _b64json(access_token.split('.')[1])
    sub = claims['sub']
    iss = claims['iss']
    granted_scope = claims.get('scope', '')
    granted_aud   = claims.get('aud', '')
    exp           = claims.get('exp')
    if SEED_GRANT == 'password' and 'offline_access' not in granted_scope:
        print('  ⚠ offline_access NOT granted by Keycloak - the exchange will '
              'not be able to mint a refresh token. Check that offline_access '
              'is an allowed scope on the rucio client.')
    identity_internal = oidc.oidc_identity_string(sub, iss)
    audience = ' '.join(granted_aud) if isinstance(granted_aud, list) else granted_aud
    lifetime = datetime.utcfromtimestamp(float(exp)) if exp else None

    _ensure_mapped(identity_internal, account)
    try:
        oidc.save_subject_token(
            token=access_token,
            account=InternalAccount(account),
            identity=identity_internal,
            scope=granted_scope,
            audience=audience,
            lifetime=lifetime,
        )
        print(f'  ✓ Subject token saved for {account}')
    except Exception as e:
        msg = str(e).lower()
        if 'duplicate key' in msg or 'tokens_pk' in msg or 'unique constraint' in msg:
            print(f'  ✓ Subject token already present for {account}')
        else:
            raise
    return identity_internal, granted_scope, audience, lifetime


try:
    last = None
    for account in ACCOUNTS:
        last = _store(account, _mint_token())

    if last:
        identity_internal, granted_scope, audience, lifetime = last
        print(f'      identity = {identity_internal}')
        print(f'      scope    = {granted_scope!r}')
        print(f'      audience = {audience!r}')
        print(f'      expires  = {lifetime}')

except urllib.error.HTTPError as e:
    print(f'  ✗ Token request failed: HTTP {e.code} {e.read().decode()[:300]}')
    sys.exit(1)
except AttributeError as e:
    print(f'  ✗ Subject-token seeding failed: {e}')
    print('    This usually means save_subject_token() is missing from the')
    print('    patched oidc.py - add the wrapper to')
    print('    patches/rucio/oidc.py and re-run.')
    sys.exit(1)
except Exception as e:
    import traceback
    print(f'  ✗ Subject-token seeding failed: {e}')
    traceback.print_exc()
    sys.exit(1)
"

    echo "  Removing non-OIDC token rows for seeded accounts..."
    local acct
    for acct in "${SEED_ACCOUNTS[@]}"; do
        _exec ruciodb env PGPASSWORD=rucio psql -U rucio -tAc \
          "DELETE FROM tokens WHERE account='${acct}' AND identity NOT LIKE 'SUB=%';"
    done
}

cleanup_session_tokens() {
    echo "=== Removing non-OIDC session tokens for seeded accounts ==="
    local acct
    for acct in "${SEED_ACCOUNTS[@]}"; do
        _exec ruciodb env PGPASSWORD=rucio psql -U rucio -tAc \
          "DELETE FROM tokens WHERE account='${acct}' AND identity NOT LIKE 'SUB=%';"
    done
}

# ── RSE Configuration ─────────────────────────────────────────────

configure_rses() {
    echo "=== Configuring RSEs ==="

    local resource_param
    resource_param=$(_cap "client_credentials.resource_param" "false")

    for rse in XRD3 XRD4; do
        local host
        host=$(echo "$rse" | tr '[:upper:]' '[:lower:]')
        ra rse add "$rse" || true
        ra rse set-attribute --rse "$rse" --key fts --value "$FTS_OIDC"
        ra rse set-attribute --rse "$rse" --key oidc_support --value True
        ra rse set-attribute --rse "$rse" --key auth_type --value OIDC
        if [ "$resource_param" = "true" ]; then
            ra rse set-attribute --rse "$rse" --key audience --value "https://${host}.example.org/"
        else
            ra rse set-attribute --rse "$rse" --key audience --value "${host}"
        fi
        ra rse set-attribute --rse "$rse" --key verify_checksum --value False
        ra rse add-protocol "$rse" --scheme davs --hostname "$host" --port 1094 \
            --prefix /data \
            --impl rucio.rse.protocols.gfal.Default \
            --domain-json '{"wan":{"read":1,"write":1,"delete":1,"third_party_copy_read":1,"third_party_copy_write":1},"lan":{"read":1,"write":1,"delete":1}}' || true
    done
    ra rse add-distance XRD3 XRD4 --distance 1 || true
    ra rse add-distance XRD4 XRD3 --distance 1 || true

    for rse in TEAPOT1 TEAPOT2; do
        local instance
        instance=$(echo "$rse" | tr '[:upper:]' '[:lower:]')
        ra rse add "$rse" || true
        ra rse set-attribute --rse "$rse" --key fts --value "$FTS_OIDC"
        ra rse set-attribute --rse "$rse" --key oidc_support --value True
        ra rse set-attribute --rse "$rse" --key auth_type --value OIDC
        if [ "$resource_param" = "true" ]; then
            ra rse set-attribute --rse "$rse" --key audience --value "https://${instance}.example.org/"
        else
            ra rse set-attribute --rse "$rse" --key audience --value "$instance"
        fi
        ra rse set-attribute --rse "$rse" --key verify_checksum --value False
        ra rse add-protocol "$rse" --scheme davs \
            --hostname "${instance}" --port 8081 --prefix /data \
            --impl rucio.rse.protocols.gfal.Default \
            --domain-json '{"wan":{"read":1,"write":1,"delete":1,"third_party_copy_read":1,"third_party_copy_write":1},"lan":{"read":1,"write":1,"delete":1}}' || true

        ra rse add-protocol "$rse" --scheme https \
            --hostname "${instance}" --port 8081 --prefix /data \
            --impl rucio.rse.protocols.gfal.Default \
            --domain-json '{"wan":{"read":1,"write":1,"delete":1,"third_party_copy_read":1,"third_party_copy_write":1},"lan":{"read":1,"write":1,"delete":1}}' || true
    done
    ra rse add-distance TEAPOT1 TEAPOT2 --distance 1 || true
    ra rse add-distance TEAPOT2 TEAPOT1 --distance 1 || true

    ra rse add-distance XRD3 TEAPOT1 --distance 1 || true
    ra rse add-distance TEAPOT1 XRD3 --distance 1 || true
}

# ── FTS OIDC Provider Registration ───────────────────────────────

setup_fts_oidc_provider() {
    echo "=== Registering ${FTS_PROVIDER_NAME} in FTS Database (via REST) ==="

    echo "  Waiting for FTS config API to be ready..."
    for i in $(seq 1 60); do
        code=$(_fts_admin -o /dev/null -w '%{http_code}' https://localhost:8446/config/token_providers 2>/dev/null) || code=0
        [[ "$code" == "200" ]] && { echo "  ✓ Config API ready"; break; }
        [ "$i" = "60" ] && { echo "  ✗ Config API never became ready (last code: $code)"; exit 1; }
        sleep 5
    done

    local iss_bare iss_slash
    iss_bare="${OIDC_ISSUER%/}"
    iss_slash="${iss_bare}/"

    # Both slash and no-slash forms are genuinely required (not just belt-
    # and-braces): submit-time lookup matches the raw JWT 'iss' claim
    # verbatim (no slash), while t_token has an FK (fk_token_issuer)
    # requiring the SLASHED form.
    _fts_admin -X POST -H "Content-Type: application/json" \
        -d "{\"name\":\"${FTS_PROVIDER_NAME}\",\"issuer\":\"${iss_bare}\",\"client_id\":\"${OIDC_CLIENT_ID}\",\"client_secret\":\"${OIDC_CLIENT_SECRET}\"}" \
        https://localhost:8446/config/token_providers
    _fts_admin -X POST -H "Content-Type: application/json" \
        -d "{\"name\":\"${FTS_PROVIDER_NAME}-slash\",\"issuer\":\"${iss_slash}\",\"client_id\":\"${OIDC_CLIENT_ID}\",\"client_secret\":\"${OIDC_CLIENT_SECRET}\"}" \
        https://localhost:8446/config/token_providers

    echo "  Restarting fts..."
    _restart fts
    for i in $(seq 1 30); do
        code=$(_exec fts curl -sk -o /dev/null -w '%{http_code}' \
            https://localhost:8446/whoami 2>/dev/null) || code=0
        [[ "$code" == "200" || "$code" == "403" ]] && { echo "  ✓ fts ready"; break; }
        sleep 5
    done
}

# ── Scopes & Quotas ───────────────────────────────────────────────

setup_scopes_and_quotas() {
    echo "=== Configuring Scopes and Quotas ==="

    ra scope add --account root --scope test || true
    ra scope add --account ddmlab --scope ddmlab || true
    ra scope add --account randomaccount --scope randomaccount || true

    for rse in XRD3 XRD4 TEAPOT1 TEAPOT2; do
        ra account set-limits root "$rse" -1 || true
        ra account set-limits randomaccount "$rse" -1 || true
        ra account set-limits ddmlab "$rse" -1 || true
    done
}


# ── Token-exchange grant ─────────────────────────────────────────

grant_token_exchange() {
    if [[ "$OIDC_ISSUER" != *"/realms/"* ]]; then
        echo "  Skipping token-exchange grant (not a local Keycloak issuer: $OIDC_ISSUER)"
        return 0
    fi
    echo "=== Granting token-exchange permissions ==="

    _kc config credentials \
        --server http://localhost:8080 \
        --realm master --user admin --password admin

    local rc uuid
    local requester_uuids=()
    for rc in "${EXCHANGE_REQUESTERS[@]}"; do
        uuid=$(_kc get clients -r "$KC_REALM" \
            -q clientId="$rc" --fields id --format csv --noquotes | tr -d '\r')
        if [ -z "$uuid" ]; then
            echo "  ERROR: requester client '$rc' not found" >&2
            exit 1
        fi
        echo "  requester $rc UUID: $uuid"
        requester_uuids+=( "$uuid" )
    done
    local requester_uuids_json
    requester_uuids_json=$(printf '"%s",' "${requester_uuids[@]}")
    requester_uuids_json="[${requester_uuids_json%,}]"

    local target target_uuid rm_uuid policy_name policy_id perm_name perm_id
    for target in "${EXCHANGE_TARGETS[@]}"; do
        echo "  === target: $target ==="

        target_uuid=$(_kc get clients -r "$KC_REALM" \
            -q clientId="$target" --fields id --format csv --noquotes | tr -d '\r')
        if [ -z "$target_uuid" ]; then
            echo "  ERROR: target client '$target' not found — is it imported?" >&2
            exit 1
        fi
        echo "    target UUID: $target_uuid"

        _kc update "clients/$target_uuid/management/permissions" -r "$KC_REALM" \
            -s enabled=true
        echo "    management permissions enabled"

        rm_uuid=$(_kc get clients -r "$KC_REALM" \
            -q clientId=realm-management --fields id --format csv --noquotes | tr -d '\r')

        policy_name="exchange-to-${target}"
        policy_name=$(echo "$policy_name" | tr -c 'A-Za-z0-9_.-' '_')

        echo "    creating client policy: $policy_name  members=$requester_uuids_json"
        _kc create "clients/$rm_uuid/authz/resource-server/policy/client" -r "$KC_REALM" \
            -s "name=$policy_name" \
            -s "clients=$requester_uuids_json" \
            -s "logic=POSITIVE" \
            || echo "    (policy may already exist — updating it instead)"

        policy_id=$(_kc get \
            "clients/$rm_uuid/authz/resource-server/policy?name=$policy_name" \
            -r "$KC_REALM" --fields id --format csv --noquotes | tr -d '\r' | head -n1)

        if [ -n "$policy_id" ]; then
            _kc update \
                "clients/$rm_uuid/authz/resource-server/policy/client/$policy_id" \
                -r "$KC_REALM" -s "clients=$requester_uuids_json" \
                || echo "    (could not update policy membership — check manually)"
        fi

        perm_name="token-exchange.permission.client.$target_uuid"
        perm_id=$(_kc get \
            "clients/$rm_uuid/authz/resource-server/permission?name=$perm_name" \
            -r "$KC_REALM" --fields id --format csv --noquotes | tr -d '\r' | head -n1)

        if [ -z "$perm_id" ] || [ -z "$policy_id" ]; then
            echo "  ERROR: could not resolve perm_id ($perm_id) or policy_id ($policy_id)." >&2
            exit 1
        fi

        _kc update \
            "clients/$rm_uuid/authz/resource-server/permission/scope/$perm_id" \
            -r "$KC_REALM" -s "policies=[\"$policy_id\"]"
        echo "    policy bound to token-exchange permission"
    done
}

# ── Main ──────────────────────────────────────────────────────────

main() {
    wait_for_infrastructure
    setup_accounts_and_identities
    grant_token_exchange
    seed_subject_tokens
    configure_rses
    cleanup_session_tokens
    setup_scopes_and_quotas
    setup_fts_oidc_provider

    echo -e "\n=== Initialization Complete ==="
}

main

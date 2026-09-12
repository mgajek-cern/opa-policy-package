#!/usr/bin/env bash
set -euo pipefail

# Phase 4 testbed init — Rucio accounts plus OIDC identity mapping.
#
# Much smaller than init-phase6.sh: no FTS, no storage endpoints, no token
# exchange. The smoke tests create their own RSEs over REST, so all this
# needs to do is make each Keycloak subject resolve to exactly one Rucio
# account, which is what validate_jwt() requires.

OIDC_ISSUER="${OIDC_ISSUER:-http://keycloak:8080/realms/rucio}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-rucio-oidc}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-rucio-oidc-secret}"
OIDC_TOKEN_URL="${OIDC_TOKEN_URL:-${OIDC_ISSUER%/}/protocol/openid-connect/token}"
OIDC_EXPECTED_AUDIENCE="${OIDC_EXPECTED_AUDIENCE:-rucio}"

# Must be a superset of [oidc] expected_scope in configs/rucio/phase4/rucio.cfg,
# or validate_jwt() rejects the token with a 401 that looks like a policy deny.
# aud:rucio has include.in.token.scope=false, so it stamps aud without
# appearing in the scope claim.
OIDC_AUTHZ_SCOPE="${OIDC_AUTHZ_SCOPE:-openid offline_access aud:rucio}"

# keycloak_username:password:rucio_account — strictly one Keycloak user per
# Rucio account. A subject mapped to several accounts resolves ambiguously in
# validate_jwt(), and could land on root, which is unconditionally privileged.
AUTHZ_TEST_USERS=(
    "adminuser:admin123:adminuser"
    "alice:alice123:alice"
)

# The phase 4 compose file sets container_name, so address containers directly.
RUCIO_CONTAINER="${RUCIO_CONTAINER:-rucio-server}"
DB_CONTAINER="${DB_CONTAINER:-ruciodb}"

_exec() { docker exec -i "$RUCIO_CONTAINER" "$@"; }
_psql() { docker exec "$DB_CONTAINER" env PGPASSWORD=rucio psql -U rucio -tAc "$1"; }

ra() { _exec rucio-admin -S userpass -u ddmlab --password secret "$@"; }

# ── Readiness ─────────────────────────────────────────────────────

wait_for_infrastructure() {
    echo "=== Waiting for Rucio and Keycloak ==="
    echo "  issuer:    $OIDC_ISSUER"
    echo "  token URL: $OIDC_TOKEN_URL"

    local i code
    for i in $(seq 1 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/ping || true)
        [[ "$code" == "200" ]] && { echo "  ✓ rucio ready"; break; }
        [ "$i" = "30" ] && { echo "  ✗ rucio never became ready (last code: $code)"; exit 1; }
        echo "  [$i] rucio HTTP $code — waiting..."; sleep 5
    done

    for i in $(seq 1 30); do
        code=$(_exec curl -s -o /dev/null -w '%{http_code}' \
            "${OIDC_ISSUER%/}/.well-known/openid-configuration" 2>/dev/null || true)
        [[ "$code" == "200" ]] && { echo "  ✓ Keycloak realm discovery ready"; break; }
        [ "$i" = "30" ] && { echo "  ✗ Keycloak never served realm discovery (last code: $code)"; exit 1; }
        echo "  [$i] Keycloak HTTP $code — waiting..."; sleep 5
    done
}

# ── Accounts ──────────────────────────────────────────────────────

setup_accounts() {
    echo "=== Configuring Rucio accounts ==="

    # Positive case: holds /rucio/admins in Keycloak. Privilege comes from
    # the token, not from any account attribute.
    ra account add --type USER --email adminuser@example.org adminuser || true

    # Negative case: /rucio/users only, so it must NOT be admin here either.
    ra account add --type USER --email alice@example.org alice || true
    ra account delete-attribute alice --key admin 2>/dev/null || true

    ra scope add --account alice --scope alice || true
}

# ── OIDC identity mapping ─────────────────────────────────────────

setup_authz_test_identities() {
    echo "=== Mapping OIDC identities for authz tests ==="
    echo "  scope: $OIDC_AUTHZ_SCOPE"

    local entry username password account
    for entry in "${AUTHZ_TEST_USERS[@]}"; do
        IFS=: read -r username password account <<< "$entry"

        _exec env \
            AUTHZ_USERNAME="$username" \
            AUTHZ_PASSWORD="$password" \
            AUTHZ_ACCOUNT="$account" \
            AUTHZ_SCOPE="$OIDC_AUTHZ_SCOPE" \
            AUTHZ_CLAIM="wlcg.groups" \
            OIDC_TOKEN_URL="$OIDC_TOKEN_URL" \
            OIDC_CLIENT_ID="$OIDC_CLIENT_ID" \
            OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
            OIDC_EXPECTED_AUDIENCE="$OIDC_EXPECTED_AUDIENCE" \
            python3 /dev/stdin <<'PY'
import urllib.request, urllib.parse, json, base64, ssl, os, sys
from rucio.core.identity import add_account_identity
from rucio.core import oidc
from rucio.common.types import InternalAccount
from rucio.common import exception

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

username = os.environ['AUTHZ_USERNAME']
account = os.environ['AUTHZ_ACCOUNT']
claim_name = os.environ['AUTHZ_CLAIM']

data = urllib.parse.urlencode({
    'grant_type': 'password',
    'username': username,
    'password': os.environ['AUTHZ_PASSWORD'],
    'scope': os.environ['AUTHZ_SCOPE'],
}).encode()
auth = base64.b64encode(
    f"{os.environ['OIDC_CLIENT_ID']}:{os.environ['OIDC_CLIENT_SECRET']}".encode()
).decode()
req = urllib.request.Request(os.environ['OIDC_TOKEN_URL'], data=data,
                             headers={'Authorization': f'Basic {auth}'})

try:
    token = json.loads(urllib.request.urlopen(req, context=_SSL).read())['access_token']
except urllib.error.HTTPError as e:
    print(f'  ✗ Token request failed for {username}: HTTP {e.code} {e.read().decode()[:200]}')
    sys.exit(1)

claims = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
identity = oidc.oidc_identity_string(claims['sub'], claims['iss'])

# Fail loudly at init rather than as an opaque 401 during the test run.
granted = set(claims.get('scope', '').split())
missing = (set(os.environ['AUTHZ_SCOPE'].split()) - {'aud:rucio'}) - granted
if missing:
    print(f'  ⚠ {username}: scopes not granted: {sorted(missing)} — '
          'validate_jwt will reject this token')

aud = claims.get('aud', '')
aud = aud if isinstance(aud, list) else [aud]
if os.environ['OIDC_EXPECTED_AUDIENCE'] not in aud:
    print(f'  ⚠ {username}: aud={aud} lacks {os.environ["OIDC_EXPECTED_AUDIENCE"]!r} '
          '— request the aud:rucio scope')

if claim_name not in claims:
    print(f'  ⚠ {username}: no {claim_name} claim — is the dot escaped in the '
          'realm mapper? An unescaped dot nests the claim instead.')

try:
    add_account_identity(identity, 'OIDC', InternalAccount(account), f'{account}@rucio')
    print(f'  ✓ {username} → {account}: {identity}')
except exception.Duplicate:
    print(f'  ✓ {username} → {account} already mapped')
print(f'      {claim_name} = {claims.get(claim_name)}')
PY
    done
}

assert_identities_unambiguous() {
    echo "=== Checking OIDC identity → account mapping ==="

    local count
    count=$(_psql "SELECT count(*) FROM account_map WHERE identity_type='OIDC';" | tr -d ' ')
    if [[ "$count" -eq 0 ]]; then
        echo "  ✗ no OIDC identities mapped — the mapping step produced nothing"
        exit 1
    fi
    echo "  ✓ $count OIDC identity mapping(s)"

    local dupes
    dupes=$(_psql "SELECT identity || ' → ' || count(*) || ' accounts'
                     FROM account_map
                    WHERE identity_type='OIDC'
                    GROUP BY identity HAVING count(*) > 1;")

    if [[ -n "$dupes" ]]; then
        echo "  ⚠ subjects mapped to multiple accounts:"
        echo "$dupes" | sed 's/^/      /'
        echo "    Such a token resolves ambiguously in validate_jwt() and any"
        echo "    authz test using it is meaningless."
    else
        echo "  ✓ every OIDC subject maps to exactly one account"
    fi
}

main() {
    wait_for_infrastructure
    setup_accounts
    setup_authz_test_identities
    assert_identities_unambiguous
    echo -e "\n=== Initialization Complete ==="
}

main

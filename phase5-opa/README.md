# rucio-opa-v4-policy

Phase 5 — OPA as PDP, OIDC token-native authorisation via URN entitlements. Keycloak issues JWTs with an `entitlements` claim; OPA evaluates entitlement strings against `data.vo.entitlement_policy` in the bundle — no Rucio DB round-trip per authorisation decision.

---

## What's new in Phase 5

| Addition | Detail |
|----------|--------|
| Entitlement-based identity | Keycloak issues JWTs with a multivalued `entitlements` claim, sourced from a user attribute (not derived from the realm's group tree) |
| Token-native privilege | `entitlements` replaces `wlcg.groups` from Phase 4 — same token-native model, URN-shaped claim instead of a group path |
| Entitlement policy bundle | `data.vo.entitlement_policy` maps URN entitlement strings → privilege level, updateable at runtime |
| Root bootstrap | `issuer == "root"` allowed unconditionally — no OIDC token needed for userpass |

**Rego policy path:** `vo/authz/v4/allow` (was `vo/authz/v3/allow`)

**OPA input shape change:** `token.groups` (Phase 4) replaced by `token.entitlements`

---

## OPA input document

```json
{
  "input": {
    "issuer": "alice",
    "action": "add_rule",
    "token": { "entitlements": [
        "urn:example:aai.example.org:group:rucio-users:role=member",
        "urn:example:aai.example.org:group:atlas-users:role=member"
    ] },
    "kwargs": { "account": "alice", "locked": false,
                "rse_expression": "CERN_DATADISK" }
  }
}
```

## Entitlement policy bundle

```json
PUT /v1/data/vo/entitlement_policy
{
  "urn:example:aai.example.org:group:rucio-admins:role=member":     "admin",
  "urn:example:aai.example.org:group:atlas-production:role=member": "admin",
  "urn:example:aai.example.org:group:rucio-users:role=member":      "user",
  "urn:example:aai.example.org:group:atlas-users:role=member":      "user"
}
```

Update at runtime without restarting Rucio or OPA.

---

## Keycloak setup

Single realm (`rucio`), no federation. Two test users:

| User | Password | Entitlements | Privilege |
|------|----------|--------------|-----------|
| `alice` | `alice123` | `...group:rucio-users:role=member`, `...group:atlas-users:role=member` | none |
| `adminuser` | `admin123` | `...group:rucio-admins:role=member`, `...group:atlas-production:role=member` | admin |

The realm's group tree (`/rucio/admins`, `/atlas/production`, etc.) is kept for realm-admin bookkeeping only. The token claim itself is sourced from each user's `entitlements` attribute via the `entitlements` client scope, not derived from group membership at token time.

---

## Install & configure

```bash
python3 -m pip install -e phase5-opa/
```

```bash
export RUCIO_POLICY_PACKAGE=rucio_opa_v4_policy
export OPA_URL=http://localhost:8181
export OPA_POLICY_PATH=vo/authz/v4/allow
export OPA_TIMEOUT=2
```

```ini
# rucio.cfg  [policy]
package = rucio_opa_v4_policy
```

## Tests

| File | Covers |
|------|--------|
| `tests/test_phase5_e2e.py` | Live OPA — entitlement privilege, user self-service, root bootstrap, runtime bundle override |
| `tests/test_phase5_smoke.py` | Live full stack — real Rucio REST API, auth, Keycloak `entitlements` claim verification, and that Rucio actually calls OPA end-to-end |

```bash
# Start the full stack (Rucio + OPA + Keycloak + PostgreSQL) once for e2e + smoke
cd phase5-opa/deploy && docker compose --profile full up -d && cd ../..

# E2E — against OPA directly
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase5_e2e.py -v

# Smoke — against Rucio's REST API + Keycloak
RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
    KEYCLOAK_URL=http://localhost:8080 \
    python3 -m pytest tests/test_phase5_smoke.py -v

# Teardown
cd phase5-opa/deploy && docker compose --profile full down -v && cd ../..
```

## Verify Keycloak issues entitlements

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/realms/rucio/protocol/openid-connect/token \
  -d "grant_type=password&client_id=rucio-oidc&client_secret=rucio-oidc-secret" \
  -d "username=alice&password=alice123&scope=openid entitlements" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo $TOKEN | cut -d. -f2 | python3 -c "
import base64, sys
print(base64.urlsafe_b64decode(sys.stdin.read() + '===').decode())
" | python3 -m json.tool
```

- Expected for `alice`: `"entitlements": ["urn:example:aai.example.org:group:rucio-users:role=member", "urn:example:aai.example.org:group:atlas-users:role=member"]`
- Expected for `adminuser`: `"entitlements": ["urn:example:aai.example.org:group:rucio-admins:role=member", "urn:example:aai.example.org:group:atlas-production:role=member"]`

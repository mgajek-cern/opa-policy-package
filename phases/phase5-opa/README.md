# rucio-opa-v4-policy

Phase 5 — OPA as PDP, OIDC token-native authorisation via URN entitlements. Keycloak issues JWTs with an `entitlements` claim; OPA evaluates entitlement strings against `data.vo.entitlement_policy` in the bundle — no Rucio DB round-trip per authorisation decision.

## What's new in Phase 5

| Addition | Detail |
|----------|--------|
| Entitlement-based identity | Keycloak issues JWTs with a multivalued `entitlements` claim, sourced from a user attribute (not derived from the realm's group tree) |
| Token-native privilege | `entitlements` replaces `wlcg.groups` from Phase 4 — same token-native model, URN-shaped claim instead of a group path |
| Entitlement policy bundle | `data.vo.entitlement_policy` maps URN entitlement strings → privilege level, updateable at runtime |
| Root bootstrap | `issuer == "root"` allowed unconditionally — no OIDC token needed for userpass |

**Rego policy path:** `vo/authz/v4/allow` (was `vo/authz/v3/allow`)

**OPA input shape change:** `token.groups` (Phase 4) replaced by `token.entitlements`

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

## Keycloak setup

Single realm (`rucio`), no federation. Two test users:

| User | Password | Entitlements | Privilege |
|------|----------|--------------|-----------|
| `alice` | `alice123` | `...group:rucio-users:role=member`, `...group:atlas-users:role=member` | none |
| `adminuser` | `admin123` | `...group:rucio-admins:role=member`, `...group:atlas-production:role=member` | admin |

The realm's group tree (`/rucio/admins`, `/atlas/production`, etc.) is kept for realm-admin bookkeeping only. The token claim itself is sourced from each user's `entitlements` attribute via the `entitlements` client scope, not derived from group membership at token time.

## Configuration

```ini
# rucio.cfg
[policy]
package = rucio_opa_v4_policy
```

| Variable | Default | Purpose |
|---|---|---|
| `OPA_URL` | `http://localhost:8181` | OPA server the policy module queries |
| `OPA_POLICY_PATH` | `vo/authz/v4/allow` | Rego rule path for this phase |
| `OPA_TIMEOUT` | `2` | Seconds before `query_opa()` fails closed |

Privilege comes from the token, so `[oidc]` in `configs/rucio/phase4/rucio.cfg`
matters as much as the above: `expected_scope` and `expected_audience` are
checked by `validate_jwt()` *before* the policy runs, and a token missing
either is rejected with a 401 that looks like a policy deny.

## Running it

`make e2e PHASE=5` — see [Quick start](../../README.md#quick-start).

`make init PHASE=5` maps each Keycloak subject to exactly one Rucio account;
without it `validate_jwt()` cannot resolve a token to an account and every
test fails with `CannotAuthenticate`.

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

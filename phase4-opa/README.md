# rucio-opa-v3-policy

Phase 4 — OPA as PDP, OIDC token-native authorisation via `wlcg.groups`. Keycloak issues JWTs with a `wlcg.groups` claim; OPA evaluates group paths against `data.vo.group_policy` in the bundle — no Rucio DB round-trip per authorisation decision.

---

## What's new in Phase 4

| Addition | Detail |
|----------|--------|
| OIDC identity provider | Keycloak (single realm `rucio`) issues JWTs with `wlcg.groups` |
| Token-native privilege | `wlcg.groups` replaces `is_root`/`is_admin` DB lookup — 0 DB calls per auth decision |
| Group policy bundle | `data.vo.group_policy` maps group paths → privilege level, updateable at runtime |
| Root bootstrap | `issuer == "root"` allowed unconditionally — no OIDC token needed for userpass |

**Rego policy path:** `vo/authz/v3/allow` (was `vo/authz/v2/allow`)

**OPA input shape change:** `is_root`/`is_admin` replaced by `token.groups`

---

## OPA input document

```json
{
  "input": {
    "issuer": "alice",
    "action": "add_rule",
    "token": { "groups": ["/rucio/users", "/atlas/users"] },
    "kwargs": { "account": "alice", "locked": false,
                "rse_expression": "CERN_DATADISK" }
  }
}
```

## Group policy bundle

```json
PUT /v1/data/vo/group_policy
{
  "/rucio/admins":     "admin",
  "/atlas/production": "admin",
  "/rucio/users":      "user",
  "/atlas/users":      "user"
}
```

Update at runtime without restarting Rucio or OPA.

---

## Keycloak setup

Single realm (`rucio`), no federation. Two test users:

| User | Password | Groups | Privilege |
|------|----------|--------|-----------|
| `alice` | `alice123` | `/rucio/users`, `/atlas/users` | none |
| `adminuser` | `admin123` | `/rucio/admins`, `/atlas/production` | admin |

The `wlcg` client scope maps Keycloak group membership to `wlcg.groups` in the JWT.

---

## Install & configure

```bash
python3 -m pip install -e phase4-opa/
```

```bash
export RUCIO_POLICY_PACKAGE=rucio_opa_v3_policy
export OPA_URL=http://localhost:8181
export OPA_POLICY_PATH=vo/authz/v3/allow
export OPA_TIMEOUT=2
```

```ini
# rucio.cfg  [policy]
package = rucio_opa_v3_policy
```

## Tests

| File | Covers |
|------|--------|
| `tests/test_phase4_e2e.py` | Live OPA — group privilege, user self-service, root bootstrap, runtime bundle override |
| `tests/test_phase4_smoke.py` | Live full stack — real Rucio REST API, auth, Keycloak `wlcg.groups` claim verification, and that Rucio actually calls OPA end-to-end |

```bash
# Start the full stack (Rucio + OPA + Keycloak + PostgreSQL) once for e2e + smoke
cd phase4-opa/docker && docker compose --profile full up -d && cd ../..

# E2E — against OPA directly
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase4_e2e.py -v

# Smoke — against Rucio's REST API + Keycloak
RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
    KEYCLOAK_URL=http://localhost:8080 \
    python3 -m pytest tests/test_phase4_smoke.py -v

# Teardown
cd phase4-opa/docker && docker compose --profile full down -v && cd ../..
```

## Verify Keycloak issues wlcg.groups

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/realms/rucio/protocol/openid-connect/token \
  -d "grant_type=password&client_id=rucio-oidc&client_secret=rucio-oidc-secret" \
  -d "username=alice&password=alice123&scope=openid wlcg" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo $TOKEN | cut -d. -f2 | python3 -c "
import base64, sys
print(base64.urlsafe_b64decode(sys.stdin.read() + '===').decode())
" | python3 -m json.tool
```

Expected for `alice`: `"wlcg.groups": ["/rucio/users", "/atlas/users"]`
Expected for `adminuser`: `"wlcg.groups": ["/rucio/admins", "/atlas/production"]`

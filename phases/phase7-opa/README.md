# rucio-opa-v6-policy

Phase 7 — authorisation moves out of Rucio's process entirely. `has_permission()`
no longer queries OPA directly (Phase 5/6's model); it calls a standalone
**DEP Authorization Service** (`services/authorization-service/`) over HTTP,
which validates the caller's own OIDC bearer token and queries OPA itself.
Same entitlement/ownership model as Phase 6 — token-native URN entitlements,
`owned_scopes`/`rule_owner`/`rule_scope` resolved from Rucio's own tables —
just relocated behind a typed REST contract instead of a Rego input document.

## What's new in Phase 7

| Addition | Detail |
|----------|--------|
| Authorization Service | A separate FastAPI service, one typed endpoint per decision (`/v1/decisions/rules/create`, `/v1/decisions/dids/attach`, ...); see `services/authorization-service/api/openapi.yaml` |
| OAuth2 bearer auth on the PEP itself | `permission.py` exchanges the issuer's identity for a token scoped to `authz-service` (RFC 8693, `pep:rucio` scope) before every decision request — authenticating to Rucio now depends on this exchange succeeding |
| Generated client, not hand-written | `rucio_authz_client`, generated from the service's own OpenAPI spec via `openapi-generator`'s `python-legacy` target — the only generator tried whose output is Python 3.9-safe, which rucio-server requires (AlmaLinux 9 / EPEL `gfal2`). See `services/authorization-service/docs/python39-constraint.md` |
| Deny-closed on every non-200 | A decision is HTTP 200 whether it permits or denies; any other status (network failure, authz-service down, malformed request) is treated as a deny by `permission.py`, never a silent pass |

**Decision endpoint base:** `AUTHZ_SERVICE_URL` (default `http://localhost:8000`), one path per action — see the OpenAPI contract for the full list. Actions without a typed endpoint (e.g. `add_account`, `approve_rule`) route through `/v1/decisions/privileged-operations`.

## Request shape

Unlike Phase 5/6's Rego input document, the request body carries only what
the PEP's own token cannot supply: resource-ownership facts resolved from
Rucio's tables, and the subject identity for logging. Claims the token
*does* carry (`entitlements`, `acr`) are read by authz-service from its own
validated bearer token, never trusted from the request body.

```json
POST /v1/decisions/rules/create
{
  "subject": {"type": "oidc_subject", "id": "alice@https://keycloak:8443/realms/rucio"},
  "rule": {
    "owner": "alice",
    "locked": false,
    "rse_expression": "CERN_DATADISK",
    "dids": [{"scope": {"name": "alice.data", "owner": "alice"}, "name": "file1"}]
  },
  "context": {"vo": "def"}
}
```

Response is always HTTP 200 on a real decision:

```json
{"decision": true, "context": {"decision_id": "...", "policy": {"id": "vo/authz/v6", "version": "..."}}}
```

## Keycloak setup

Same realm model as Phase 6, plus one addition: `authz-service` needs its own
token-exchange target, so `grant_token_exchange()` in `init-phase7.sh` runs
against it alongside the storage/FTS clients. rucio-server's exchanged token
carries `aud=authz-service` and the `pep:rucio` scope; authz-service verifies
signature, audience, and required scope itself before ever consulting OPA.

## Installation

```bash
python3 -m pip install -e phases/phase7-opa/
```

Regenerating `rucio_authz_client` after a spec change:

```bash
cd services/authorization-service
make generate-client-phase7
```

## Configuration

```ini
# rucio.cfg
[policy]
package = rucio_opa_v6_policy
```

| Variable | Default | Purpose |
|---|---|---|
| `AUTHZ_SERVICE_URL` | `http://localhost:8000` | Base URL of the Authorization Service |
| `AUTHZ_OIDC_AUDIENCE` | `authz-service` | Audience requested when exchanging for a scoped token |
| `AUTHZ_REQUIRED_SCOPE` | `pep:rucio` | Scope requested alongside the audience |
| `AUTHZ_VO` | `def` | VO sent in every decision request's `context` |
| `RUCIO_OPA_DEBUG_INPUT` | unset | `1`/`true` logs the full request body per decision at WARNING |

`Unable to load schema module rucio_opa_v6_policy.schema from policy package,
falling back to generic` on startup is expected, same as prior phases.

## Scope

OIDC-authenticated accounts only. `get_token_for_account_operation()`
requires an existing subject token on file for the issuer; x509/userpass/SSH/
GSS identities have none and are denied explicitly rather than falling back
to some other path. This is a deliberate scope decision — see
`permission.py`'s module docstring.

## Running it

`make certs && make e2e PHASE=7` then `make test PHASE=7` — see
[Quick start](../../README.md#quick-start). `make init PHASE=7` must complete
fully before any test run: it bootstraps `ddmlab`'s account/identity/subject
token, grants the token-exchange permission for `authz-service`, and verifies
the exchange succeeds — skipping or interrupting it leaves accounts unable to
authenticate at all, since `has_permission()` now gates authentication itself.

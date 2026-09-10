# rucio-opa-v5-policy

Phase 6 — OPA as PDP, OIDC token-native authorisation via URN entitlements
(same model as Phase 5), demonstrated end to end against real third-party-copy
transfers through FTS — XRootD (XRD3 → XRD4), Teapot WebDAV
(TEAPOT1 → TEAPOT2) and both cross-protocol directions — with OIDC token
exchange validated on the wire by each storage endpoint's own token
enforcement.

---

## What's new in Phase 6

| Addition | Detail |
|----------|--------|
| Real transfers, not just policy evaluation | Rucio → FTS → XRootD/Teapot third-party copy, driven by RFC 8693 OIDC token exchange, not simulated |
| Two storage protocols | XRootD SciTokens (`xrd3`/`xrd4`) and Storm-WebDAV (`teapot1`/`teapot2`), plus the cross-protocol pairs |
| RSE-name allowlist | `XRD3`/`XRD4`/`TEAPOT1`/`TEAPOT2` don't follow the `NAME_TYPE` naming convention Phase 1–5 enforce; added as an explicit allowlist in Rego rather than relaxing the convention globally |
| Storage-side enforcement | XRootD validates the exchanged SciToken's issuer/audience natively via `scitokens.conf`, Teapot via its Storm-WebDAV storage-area config — separate enforcement points from Rucio's `has_permission()`/OPA, not routed through this package |

**Rego policy path:** `vo/authz/v5/allow` (same package version as Phase 5 — no entitlement-model changes, only the RSE allowlist addition)

---

## What this does *not* yet prove

Phase 6 exercises the transfer/token-exchange path end to end, but the
Rucio-side authorization calls in the test suite currently run under
**userpass** (account `root`, via `configs/rucio/userpass-client.cfg`), not
OIDC — so `_is_privileged`/entitlement-based checks in the Rego are not yet
exercised by this specific test. The exchanged storage tokens *do* carry the
`entitlements` claim, but the endpoints that consume them authorize on
issuer/audience/scope, and `_extract_entitlements` has no populated source
under userpass. The transfer's storage-endpoint leg *is* genuinely
OIDC/token-exchange-driven end to end; only the Rucio-API leg still uses
userpass in the current tests. Closing that gap (an OIDC-authenticated
privileged action, e.g. `adminuser` calling `add_rse`) and the ADR's
`transfer.authorize` operation are tracked in [BACKLOG.md](../BACKLOG.md).

---

## OPA input document

Identical shape to Phase 5 — see [phase5-opa/README.md](../phase5-opa/README.md#opa-input-document).
No new input fields were added for the transfer path; RSE identity is
validated by name against the allowlist below, not passed as a separate
privilege input.

## RSE naming allowlist

```json
PUT /v1/data/vo/policy
{
  "known_rse_types": [ "DATADISK", "TAPE", "SCRATCHDISK" ],
  "allowlisted_rse_names": ["XRD3", "XRD4", "TEAPOT1", "TEAPOT2"]
}
```

These names bypass the `NAME_TYPE` regex check entirely; every other RSE
name still requires it. Update at runtime without restarting Rucio or OPA.

---

## Keycloak setup

Same realm model as Phase 5 (`entitlements` claim, per-user attribute), plus
token-exchange audience clients for the transfer path itself (`xrd3`, `xrd4`,
`teapot1`, `teapot2`, `fts`) — see `deploy/configs/keycloak/realm.json`.

Two Keycloak-specific details the LS AAI profile in
[dep-dlm-bbmri](https://github.com/RI-SCALE/dep-dlm-bbmri) doesn't need, both
handled by `init-testbed.sh`:

- **Token-exchange permissions are per target client.** Keycloak refuses an
  exchange with `403 access_denied "Client not allowed to exchange"` unless
  fine-grained authz is enabled on the *target* client and a client policy
  naming the requester is bound to its `token-exchange` permission. This holds
  even when requester and target are the same client, so
  `grant_token_exchange()` runs against every audience client at init time.
- **Subject tokens are seeded with the password grant.** Keycloak only grants
  `offline_access` — and only returns a refresh token — for a real user
  session, so a `client_credentials` service-account token fails the
  `expected_scope` gate in `get_token_for_account_operation()`. Seeding runs as
  `randomaccount`. Audience comes from the `aud:<name>` client scopes rather
  than RFC 8707's `resource` parameter, which Keycloak 23 doesn't implement.

---

## Install & configure

```bash
python3 -m pip install -e phase6-opa/
```

```bash
export RUCIO_POLICY_PACKAGE=rucio_opa_v5_policy
export OPA_URL=http://localhost:8181
export OPA_POLICY_PATH=vo/authz/v5/allow
export OPA_TIMEOUT=2
```

```ini
# rucio.cfg  [policy]
package = rucio_opa_v5_policy
```

`Unable to load schema module rucio_opa_v5_policy.schema from policy package,
falling back to generic` on startup is expected: Rucio's policy-package loader
looks for an optional `schema` submodule, and Phase 6 deliberately doesn't
override the DID/RSE schema.

## Running the testbed

Certs are bind-mounted read-only into every container at startup, so they
must exist on the host **before** `docker compose up` — generate them
first, then start the stack, then initialize RSEs/accounts:

```bash
# 1. Generate CA + host certs (xrd3, xrd4, teapot1, teapot2, rucio-server, fts, keycloak)
cd phase6-opa/deploy/scripts && ./generate-certs.sh && cd ../../..

# 2. Start the full stack
cd phase6-opa/deploy && docker compose up -d && cd ../..

# 3. Grant token exchange, register RSEs/accounts/scopes, seed OIDC subject
#    tokens, register the FTS token provider
cd phase6-opa/deploy/scripts && ./init-testbed.sh && cd ../../..

# 4. Run the transfer tests
docker compose -f phase6-opa/deploy/docker-compose.yml exec -T rucio-client \
    python3 -m pytest /tests/test_phase6_smoke.py -v

# Teardown
cd phase6-opa/deploy && docker compose down -v && cd ../..
```

`init-testbed.sh` resolves `docker-compose.yml` relative to its own location,
so it can be run from either `deploy/` or `deploy/scripts/`. Its OIDC settings
default to the local Keycloak realm and are env-overridable — pointing the same
script at LS AAI is a matter of setting `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` and `OIDC_EXPECTED_AUDIENCE`.

## Verify the transfers completed

```bash
docker compose -f phase6-opa/deploy/docker-compose.yml exec -T rucio-client \
    rucio rule list --account root
```

Expected: `REPLICATING` → `OK` rules targeting `XRD4` (sourced from `XRD3`),
`TEAPOT2` (from `TEAPOT1`), and the cross-protocol pairs.

Seeded subject tokens, if the transfers stall at `STUCK`:

```bash
docker exec deploy-ruciodb-1 env PGPASSWORD=rucio psql -U rucio -tAc \
  "SELECT account, oidc_scope, audience FROM tokens WHERE identity LIKE 'SUB=%';"
```

`oidc_scope` must contain everything in `rucio.cfg`'s `expected_scope` and
`audience` must contain its `expected_audience`, or
`get_token_for_account_operation()` refuses to exchange and the submitter
fails with `Could not procure source token`.

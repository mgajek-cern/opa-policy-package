# Backlog

Work identified but not yet scheduled into a phase, in planned sequence.

## 1. [x] Switch Phase 4 Keycloak realm from `wlcg.groups` to URN entitlements

Preserving the same group information, e.g.:
```json
"entitlements": ["urn:example:aai.example.org:group:rucio-admins:role=member"]
```
Touches `phase4-opa/deploy/keycloak-realm.json` (claim mapper),
`phase4-opa/rego/authz.rego` (`_extract_groups` / `_group_privilege`
lookup), and `phase4-opa/deploy/ingest_policies.py` (bundle keys).
No changes needed in Rucio or the Python permission module.

## 2. [x] FTS + real storage-endpoint integration

One source and one destination RSE supporting third-party copy (e.g. Teapot
or XrootD), OIDC-enabled. Refer to
[dep-dlm-testbed](https://github.com/RI-SCALE/dep-dlm-testbed).

## 3. [x] Close the OIDC → has_permission() gap

`_extract_entitlements()` read `issuer.oidc_token_info`; `issuer` is an `InternalAccount`, a name wrapper that never carried claims. The function returned `[]` for every request, so `_is_privileged` was reachable only via the `input.issuer == "root"` bootstrap rule and every entitlement-driven rule was dead in a live stack.

Fixed for phase 6 by decoding the JWT payload where the token is validated and threading it to `request.environ['token_claims']` — four patches in `patches/rucio/` plus the policy module. Verified with a real Keycloak token reaching the OPA input document as `token.entitlements`. See [docs/design/design-001-token-claims-to-opa.md](./docs/design/design-001-token-claims-to-opa.md).

## 4. [ ] Stand up the Authorization Service ([docs/adrs/adr-001-authz-service.md](./docs/adrs/adr-001-authz-service.md))

1. Thin passthrough to the existing `authz_v3` Rego — validates the
   `/v1/authorize` contract and operation-name mapping, no behavior change.
2. Swap `rucio_opa_v3_policy/permission.py` to call it instead of OPA
   directly; Phase 4 smoke tests should pass unchanged.
3. Fold in the IAM/token-centric `transfer.authorize` path (introspection +
   storage-endpoint simulation) as its own e2e surface — by this point, real
   storage-endpoint behavior from step 2 informs this instead of guessing.

Claims "Phase 5" — sequencing after storage integration resolves the earlier
open question of which item gets that label.

## 5. [ ] Fine-grained, resource-level permissions

Current model is role/ownership-based. Per-RSE/per-scope ABAC and
time/context constraints (rule expiry, maintenance windows) need a use-case/
persona overview first, so policies are modeled against real access patterns
rather than guessed ABAC shape.

##  6. [ ] Consolidate knowledge in the [dep-dlm-testbed repository](https://github.com/RI-SCALE/dep-dlm-testbed.git)

Capture the relevant implementation details, configuration, integration steps
and lessons learned in dep-dlm-testbed to make the setup reproducible and
reusable.

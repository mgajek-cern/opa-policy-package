# Backlog

Work identified but not yet scheduled into a phase, in planned sequence.

## 1. [x] Switch Phase 4 Keycloak realm from `wlcg.groups` to URN entitlements

Preserving the same group information, e.g.:
```json
"entitlements": ["urn:example:aai.example.org:group:rucio-admins:role=member"]
```

## 2. [x] FTS + real storage-endpoint integration

One source and one destination RSE supporting third-party copy (e.g. Teapot
or XrootD), OIDC-enabled. Refer to [dep-dlm-testbed](https://github.com/RI-SCALE/dep-dlm-testbed).

## 3. [x] Close the OIDC → has_permission() gap. See [docs/design/design-001-token-claims-to-opa.md](./docs/design/design-001-token-claims-to-opa.md).

## 4. [ ] Stand up the Authorization Service ([docs/adrs/adr-001-authz-service.md](./docs/adrs/adr-001-authz-service.md))

## 5. [ ] Fine-grained, resource-level permissions

Current model is role/ownership-based. Per-RSE/per-scope ABAC and
time/context constraints (rule expiry, maintenance windows) need a use-case/
persona overview first, so policies are modeled against real access patterns
rather than guessed ABAC shape.

##  6. [ ] Consolidate knowledge in the [dep-dlm-testbed repository](https://github.com/RI-SCALE/dep-dlm-testbed.git)

Capture the relevant implementation details, configuration, integration steps
and lessons learned in dep-dlm-testbed to make the setup reproducible and
reusable.

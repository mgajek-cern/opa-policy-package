# Backlog

Work identified but not yet scheduled into a phase, in planned sequence.

## 1. [x] Switch Phase 4 Keycloak realm from `wlcg.groups` to URN entitlements

Preserving the same group information, e.g.:
```json
"entitlements": ["urn:example:aai.example.org:group:rucio-admins:role=member"]
```

## 2. [x] FTS + real storage-endpoint integration

One source and one destination RSE supporting third-party copy (e.g. Teapot or XrootD), OIDC-enabled. Refer to [dep-dlm-testbed](https://github.com/RI-SCALE/dep-dlm-testbed).

## 3. [x] Close the OIDC → has_permission() gap. See [design-001-token-claims-to-opa.md](./docs/design/design-001-token-claims-to-opa.md).

## 4. [x] Resource-level ownership resolved against the DB

`is_scope_owner()` replaces the name-prefix check for DIDs, and `get_rule()` supplies rule owner and target scope for `del_rule`/`update_rule`, in phases 4/5/6. See [design-003-scope-ownership.md](docs/design/design-003-scope-ownership.md) and [design-004-rule-ownership.md](docs/design/design-004-rule-ownership.md).

## 5. [ ] Attribute- and context-based permissions

Per-RSE/per-scope ABAC and time constraints (rule expiry, maintenance windows), blocked on a use-case and persona overview rather than on implementation.

## 6. [ ] Stand up the Authorization Service ([adr-001-authz-service.md](./docs/adrs/adr-001-authz-service.md))

## 7. [ ] Consolidate knowledge in the [dep-dlm-testbed repository](https://github.com/RI-SCALE/dep-dlm-testbed.git)

Capture the relevant implementation details, configuration, integration steps
and lessons learned in dep-dlm-testbed to make the setup reproducible and
reusable.

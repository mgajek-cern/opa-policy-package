# Design 008: DEP persona entitlements

**Status:** accepted.

**Related:** [design-003](./design-003-scope-ownership.md) (scope
ownership), [design-004](./design-004-rule-ownership.md) (rule ownership).

## Summary

Three DEP personas from the C4 architecture overview (DEP Operator, DEP
End User, Model Developer) get dedicated Keycloak entitlement URNs. Each
maps onto an *existing* privilege tier — no new Rego branch, no changes to
`authz.rego` or the Authorization Service's decision logic. This adds
claims and a mapping only.

Dedicated URNs, rather than reusing `rucio-admins`/`rucio-users` directly,
make the persona distinction visible in the token itself — giving the
Authorization Service, and any future AI Models repo or Credit Management
System authz that reads the same entitlements, a real hook, without
requiring Rucio's policy to know or care about it.

## Decision

The three personas are drawn at the *platform* layer — they describe what
someone does across the whole DEP (repository access, AI Models repo, HPC
scaling, credit tracking), not what a single Rucio call does. Every
Rucio-facing action these personas need is already covered by the existing
admin/user tiers and the ownership-based self-service rules from
design-003/004, so no new Rego branch is needed. Where DEP End User and
Model Developer actually differ from each other is entirely outside
Rucio's authz surface (which repos/HPC/credit endpoints they can reach) —
not something this policy package decides.

**Tier assignment:** DEP Operator → `"admin"`. DEP End User and Model
Developer → `"user"`.

| Action | DEP Operator | DEP End User | Model Developer |
|---|---|---|---|
| `add_rse`, `update_rse`, `del_rse` | ✅ (privileged) | ❌ | ❌ |
| `add_rse_attribute`, `del_rse_attribute` | ✅ (privileged) | ❌ | ❌ |
| `add_protocol` / `update_protocol` / `del_protocol` | ✅ (privileged) | ❌ | ❌ |
| `add_rule` (own account, owned scope) | ✅ | ✅ (self-service, "user" tier) | ✅ (self-service, "user" tier) |
| `del_rule` / `update_rule` (own rules) | ✅ | ✅ (own only) | ✅ (own only) |
| `add_did` / `add_dids` (owned scope) | ✅ | ✅ (own scope) | ✅ (own scope) |
| `attach_dids*` / `detach_dids` (owned scope) | ✅ | ✅ (own scope) | ✅ (own scope) |
| `add_replicas` (owned scope, valid RSE) | ✅ | ✅ ("user" tier) | ✅ ("user" tier) |
| `delete_replicas` (owned scope) | ✅ | ✅ ("user" tier) | ✅ ("user" tier) |
| privileged-operations catch-all (`add_account`, `approve_rule`, ...) | ✅ (privileged only) | ❌ | ❌ |

## Implementation

Entitlement URNs:

```
urn:example:aai.example.org:group:dep-operator:role=member
urn:example:aai.example.org:group:dep-end-user:role=member
urn:example:aai.example.org:group:model-developer:role=member
```

`entitlement_policy` additions:

```json
{
  "urn:example:aai.example.org:group:dep-operator:role=member":    "admin",
  "urn:example:aai.example.org:group:dep-end-user:role=member":    "user",
  "urn:example:aai.example.org:group:model-developer:role=member": "user"
}
```

## Testing

- [ ] Add the three groups/URNs to `configs/keycloak/phase6/realm.json`
      (the merged realm), assign to (new or existing) test users
- [ ] Extend the `entitlement_policy` bundle with the three mappings above
- [ ] Add `AUTHZ_TEST_USERS` entries and any scope/account bootstrap in
      `scripts/init-phase6.sh`, mirroring `randomaccount`/`adminuser`
- [ ] Add `TestDepOperatorAuthorisation` / `TestDepEndUserAuthorisation` /
      `TestModelDeveloperAuthorisation` classes in `tests/test_phase6_rucio.py`
      (and `tests/test_phase6_opa.py` for the direct-OPA path), asserting
      each persona lands on its mapped tier — no new denial/permit
      branches expected
- [ ] Update `phases/phase6-opa/README.md`'s test-user table

## Non-goals

- **Model Developer needing broader-than-user Rucio access** (e.g. bulk
  `add_replicas` across scopes it doesn't own, for staging training data)
  — would require a new Rego branch. Not built; add if a real use case
  surfaces.
- **DEP Operator needing narrower-than-admin access** (e.g. RSE management
  without `approve_rule`) — would require splitting the privileged-operations
  catch-all, which is currently all-or-nothing. Not built; add if needed.

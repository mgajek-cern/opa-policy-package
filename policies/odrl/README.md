# ODRL representation of the phase 4–6 Rego

This directory holds the phase 4, 5 and 6 authorisation policy expressed as ODRL 2.2. It was derived
from `policies/rego/phase{4,5,6}/authz.rego`, which runs against the target workflow. The point is to
learn what the ODRL has to contain so that the Rego can later be generated from it. Until a
translator exists, the Rego stays authoritative and this is a reviewed mirror of it.

All IRIs use `https://example.org/`. Replace them with a namespace you control.

## Layout

| File | Contains | Becomes, in the lifecycle |
|---|---|---|
| `policies/rucio-authz.odrl.jsonld` | One `odrl:Set` with 29 permissions and 4 shared constraints. It is phase-independent. | The rule structure of `authz.rego`. |
| `profile/rucio-authz-profile.ttl` | The Rucio actions, left operands and classes, each annotated with its OPA input path and Rego predicate. | A Rego helper library, which is fixed code. |
| `policies/bindings/phase{4,5,6}.jsonld` | The party collections (which claim values mean admin or user), the RSE types, the RSE allowlist, and which JWT claim `membershipClaim` reads. | `PUT /v1/data/vo/policy` plus the group or entitlement bundle. |

The policy is identical across phases 4, 5 and 6. The Rego files differ only in what the bindings
capture: the membership claim (`wlcg.groups` versus `entitlements`) and the phase 6 RSE-name
allowlist. ODRL makes that separation explicit, where the Rego leaves it implicit.

## Rule inventory

| ODRL rule (`pol:rule/…`) | Assignee | Rego |
|---|---|---|
| `add_rule/owner` | `party:account` | `_perm_add_rule`, first clause |
| `add_rule/privileged` | `party:privileged` | `_perm_add_rule`, second clause |
| `del_rule/owner`, `del_rule/privileged` | account, privileged | `_perm_rule_owner` |
| `update_rule/owner`, `update_rule/privileged` | account, privileged | `_perm_rule_owner_and_data` |
| `add_rse/privileged` | privileged | `_perm_add_rse` |
| `update_rse/privileged` | privileged | `_perm_update_rse` (both clauses, as `or`) |
| `del_rse`, `add_rse_attribute`, `del_rse_attribute` | privileged | `_rse_actions - {add_rse, update_rse}` |
| `{add_did, add_dids, attach_dids, detach_dids, attach_dids_to_dids}/privileged` | privileged | `_perm_did_action`, first clause |
| `{add_did, attach_dids, detach_dids}/scope-owner` | account | `scope in owned_scopes` |
| `add_dids/scope-owner` | account | `scope in owned_scopes` **or** the `every` clause |
| `attach_dids_to_dids/scope-owner` | account | `scope in owned_scopes` **or** the attachments clause |
| `{add,del,update}_protocol/privileged` | privileged | `_perm_protocol_action` (both clauses, as `or`) |
| `add_replicas/privileged`, `add_replicas/user` | privileged, user | `_perm_add_replicas`, first and second clauses |
| `update_replicas_states`, `delete_replicas` | privileged | `_replica_actions - {add_replicas}` |
| `unlisted/privileged` | privileged | `not _is_known_action(input.action)` |

Mapping the parties:

- `party:privileged` is `_is_privileged`: the account is `root`, or a membership claim maps to admin.
- `party:user` is `_has_privilege_level("user")`.
- `party:account` is any issuer. The ownership rules require no claim at all.

## What ODRL does not carry

These parts are defined by the profile. A translator has to implement them, because no ODRL
evaluator will infer them.

**Default deny.** ODRL does not say that an unmatched request is denied. The profile states it, and
the Rego has it as `default allow := false`.

**Undefined means unsatisfied.** The ownership rules fail closed when `permission.py` cannot resolve a
fact. That works only because a missing `rule_owner` makes the constraint false rather than
unevaluable. The profile states this convention. A generic ODRL evaluator might instead treat a
missing value as an error or skip the constraint.

**Variable binding.** ODRL has no way to express "the rule's account equals the requesting account".
Every ownership check is therefore a boolean left operand such as `rucio:ruleOwnerIsIssuer eq true`,
whose meaning is a Rego comparison. This is the usual pattern, and it is how
[odrl-pap](https://github.com/wistefan/odrl-pap) mappings work, but most of the policy's logic lives in
the profile rather than in the ODRL.

**The catch-all.** `rucio:unlistedAction` stands for any Rucio action missing from the profile's action
list. That list must match `_all_known_actions` exactly. Adding an action to the profile without
giving it rules moves that action out of privileged-only.

**No prohibitions.** Constraints that also bind admins, such as RSE naming and scheme allowlists, sit
inside the privileged permissions rather than in `odrl:Prohibition`. A prohibition such as "no
`add_rse` when the name doesn't conform" fails open when its constraint can't be evaluated, which is
the wrong direction for authorisation.

## Things the translation surfaced

1. **`attach_dids_to_dids` needs only *one* owned attachment scope.** `add_dids` requires every scope
   to be owned, but this clause iterates `attachments[_]`, so a single owned attachment allows the
   whole request. The name `anyAttachmentScopeOwned` makes that visible. As far as I recall, upstream
   `perm_attach_dids_to_dids` checks each attachment, so check whether the difference is intended.
2. **The generic `scope in owned_scopes` clause applies to every DID action**, including `add_dids`
   and `attach_dids_to_dids`, as an extra `or` branch. It is harmless while the gateway sends no
   top-level `scope` for those actions, but nobody chose it for them.
3. **Ownership needs no membership claim.** An account with no groups or entitlements can still add
   DIDs in its own scopes and manage its own rules. That is consistent with
   `test_self_service_unaffected_by_acr`. It is just more visible as `assignee: party:account` than it
   is in the Rego.
4. **`approve_rule` is reached only through `unlistedAction`.** The profile agrees with the current
   Rego, not with design-004, which describes `approve_rule` as explicitly dispatched.

## Requiring MFA for privilege

`data.vo.policy.required_acr` is unset by default in every phase, so the bindings omit it. To require
MFA for the OIDC privilege path, but not for root, change the `party:privileged` refinement to:

```json
"or": { "@list": [
  { "leftOperand": "rucio:account", "operator": "eq", "rightOperand": "root" },
  { "and": { "@list": [
    { "leftOperand": "rucio:membershipClaim", "operator": "isAnyOf", "rightOperand": ["…admin claims…"] },
    { "leftOperand": "rucio:acr", "operator": "eq", "rightOperand": "https://refeds.org/profile/mfa" }
  ]}}
]}
```

## Towards generating the Rego

The obvious existing route is [odrl-pap](https://github.com/wistefan/odrl-pap). Its `mapping.json`
maps each namespaced ODRL term to a Rego method, and it serves the resulting policies and data as OPA
bundles. The `rucio:regoPredicate` annotations in the profile are a first draft of that mapping.

odrl-pap's built-in request helpers target API gateways (APISIX and Kong), not Rucio's input
document. You would therefore need a `rucio` method package that reads `input.kwargs` and
`input.token`.

To check a generated policy against the hand-written one, run both sets of `tests/test_phaseN_opa.py`
cases against each.

## Not covered

The phase 1–3 packages (`vo.authz`, `vo.authz.v2`) were not translated. They depend on `is_root` and
`is_admin` flags, name-prefix scope ownership and a `mock` scope stub. Encoding those in ODRL would
enshrine exactly what designs 003 and 004 replaced.

## Checks run

Every file parses as RDF (Turtle and JSON-LD). The JSON-LD was parsed with an offline stand-in for
the ODRL context. Every action and left operand used is declared in the profile, and the profile's
action list equals the Rego's `_all_known_actions`. Every referenced constraint and party resolves,
and every `or` is a well-formed list. Decisions have not been checked against an ODRL evaluator or
against OPA.

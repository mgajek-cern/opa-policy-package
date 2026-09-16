# Design 005: Authorization Service API

**Status:** proposed (2026-09-16).

**Implements:** the ADR "API-first Authorization Service vs Direct OPA
Integration" (proposed 2026-07-07).

**Baseline:** the phase 6 policy package and Rego, with ownership semantics from
design-003 and design-004, tested end to end for DEP DLM.

**Draft contract:** [`services/authorization-service/api/openapi.yaml`](../../services/authorization-service/api/openapi.yaml).

## Summary

The service exposes **one typed endpoint per operation**, so a generated client
has one function per decision: `authorize_rule_create(...)`,
`authorize_protocol_delete(...)`, and so on. There is no generic evaluation
endpoint. Operations with no policy of their own, today phase 6's
privileged-only catch-all, share one typed endpoint that carries only the
operation's name.

Phase 7 of the policy package replaces the direct OPA call with this client.

## On the ADR

The decision is sound. Its strongest argument is not Rucio: the storage path has
no plugin model, so without a contract IAM would need its own OPA integration.

This design proposes four amendments to the ADR:

1. **Borrow AuthZEN's information model.** The ADR's
   operation/subject/resource/context is essentially the subject, action,
   resource and context of OpenID AuthZEN Authorization API 1.0, a Final
   Specification since January 2026. Reusing its vocabulary and its decision
   semantics costs nothing, even though this contract does not expose AuthZEN
   endpoints (see Options).
2. **State availability and failure behaviour.** Every Rucio write passes
   through `has_permission`, so an outage of the service is an outage of Rucio
   writes. PEPs fail closed. The ADR should say so and set a latency budget.
3. **Decide PEP authentication and subject trust.** Once decisions cross a
   network, who may assert which claims is an architectural decision.
4. **Assign responsibility for resource facts.** Phase 6 works because Rucio
   resolves ownership from its own database. IAM cannot do that for storage
   requests.

## Options

| Option | Generated client | Problem |
|---|---|---|
| A. One generic evaluation endpoint (AuthZEN) | One function taking free-form `properties` | Typing is lost at the boundary where it matters. Wrong shapes surface as denies, not as errors. |
| B. One endpoint with a `oneOf` union on operation | Varies by generator; `oneOf` with a discriminator is a common source of friction | One URL hides the operation from logs, gateways and rate limits. |
| C. Typed endpoints plus AuthZEN for the rest | Typed functions and one generic function | Two styles in one client. The generic route is where mistakes go unnoticed. |
| **D. One typed endpoint per operation** | One typed function per decision | More endpoints, and the long tail needs a route of its own. |

**Chosen: D.** The consumer wants explicit functions, and a policy package
calling `authorize_rse_attribute_set(rse=..., attribute=...)` is easier to review
than one building `properties` dicts.

The cost is interoperability. A PEP that already speaks AuthZEN cannot use
this service unchanged. Adding the AuthZEN endpoint later is additive, so that
option stays open.

## Decision

### Operation catalogue

Every phase 6 known action has its own endpoint. Operation names are domain
terms, independent of Rucio's action names.

| Operation | Endpoint | Phase 6 action(s) | Phase 6 policy reads |
|---|---|---|---|
| `rule.create` | `POST /v1/decisions/rules/create` | `add_rule` | owner, locked, RSE expressions, DID scope owners |
| `rule.update` | `POST /v1/decisions/rules/update` | `update_rule` | rule owner, target scope owner, reassignment |
| `rule.delete` | `POST /v1/decisions/rules/delete` | `del_rule` | rule owner |
| `did.create` | `POST /v1/decisions/dids/create` | `add_did`, `add_dids` | DID scope owners |
| `did.attach` | `POST /v1/decisions/dids/attach` | `attach_dids`, `attach_dids_to_dids` | parent scope owners |
| `did.detach` | `POST /v1/decisions/dids/detach` | `detach_dids` | parent scope owner |
| `rse.create` | `POST /v1/decisions/rses/create` | `add_rse` | RSE name |
| `rse.update` | `POST /v1/decisions/rses/update` | `update_rse` | new RSE name, if renamed |
| `rse.delete` | `POST /v1/decisions/rses/delete` | `del_rse` | privilege |
| `rse.attribute.set` | `POST /v1/decisions/rses/attributes/set` | `add_rse_attribute` | privilege |
| `rse.attribute.delete` | `POST /v1/decisions/rses/attributes/delete` | `del_rse_attribute` | privilege |
| `protocol.create` | `POST /v1/decisions/protocols/create` | `add_protocol` | scheme |
| `protocol.update` | `POST /v1/decisions/protocols/update` | `update_protocol` | scheme |
| `protocol.delete` | `POST /v1/decisions/protocols/delete` | `del_protocol` | scheme, if present |
| `replica.register` | `POST /v1/decisions/replicas/register` | `add_replicas` | RSE name, user-level claim |
| `replica.delete` | `POST /v1/decisions/replicas/delete` | `delete_replicas` | privilege |
| *(named)* | `POST /v1/decisions/privileged-operations` | everything else: `add_account`, `add_scope`, `approve_rule`, ... | privilege |

Two rules apply:

- **Each operation gets its own request schema, even when the fields are
  identical.** `RseDeleteRequest` and `ReplicaDeleteRequest` look the same
  today. Separate schemas let either one gain fields later without renaming
  another operation's generated model.
- **Operations sharing a Rucio action share an endpoint.** `add_did` and
  `add_dids` both map to `did.create` with a list, and `attach_dids` and
  `attach_dids_to_dids` both map to `did.attach`.

### The privileged-operations endpoint

Rucio's permission layer has many more actions than phase 6 lists, and every
unlisted one reaches the catch-all: privileged subjects only. The root bootstrap
depends on these actions (`add_account`, `add_scope`, `add_identity`, ...), so
phase 7 cannot work without a route for them. A generated function per Rucio
action would put Rucio's whole action list into the contract. The
`/v1/decisions/privileged-operations` endpoint gives them one typed function
instead:

```json
{ "subject": { "type": "rucio_account", "id": "root" },
  "operation": "add_account",
  "context": { "vo": "def" } }
```

- The operation carries **a name and no arguments**. That is the property
  that keeps this within the ADR's rule against opaque passthrough: no request
  data is forwarded, and the policy decides on the subject alone.
- A request naming an operation that has its own endpoint (`add_rule`,
  `del_protocol`, ...) is rejected with 400. Each operation has exactly one
  route, so one question can never get two answers.
- **Promotion is the extension path.** When an operation needs a real policy
  (for example, users managing their own account identities), it gets its own
  endpoint. Once the endpoint exists, the operation's name is rejected on this
  route.

### Request model

**Subject.** `{type, id, properties: {token}}`. `type` is `rucio_account`
(where `id` is the resolved account) or `oidc_subject` (where `id` is
`sub@iss`, reserved for IAM). `token` carries the audit identifiers the ADR
requires (`iss`, `sub`, `jti`, `aud`) and the claims the policy reads
(`entitlements`, `acr`), which is the phase 6 allowlist. Phase 4's `groups` is
not part of the contract. Root has no token.

**Trust model.** PEPs authenticate as OAuth2 clients using client credentials,
and subject claims are *asserted by the authenticated PEP*. The service does not
re-validate the user's token. The `pep:rucio` scope grants access to every
endpoint. IAM gets its own scope when it gets endpoints. Every decision records
which PEP asserted which claims.

Forwarding the raw token for the service to validate was not chosen for v1. It
spreads bearer tokens to one more component and duplicates validation Rucio
already performs. It remains open if a regulatory context requires independent
verification.

**Resource facts are supplied by the PEP, as owners.** Requests carry
`scope: {name, owner}` and `rule: {id, owner, target}` rather than phase 6's
`owned_scopes`, which answered "which of these does the caller own?" and so made
half the decision inside the PEP. Sending owners lets the policy compare.

**Multiple resources.** A request naming several resources (`dids`,
`attachments`) is permitted only if every one is permitted. The contract fixes
this, so individual policies cannot choose differently.

**Context.** `vo` is required, so a multi-VO deployment needs no breaking change.

**No `X-Request-ID` header.** Correlation uses `decision_id` in the response,
which the PEP logs next to its own request id. Adding the header later is
additive.

### Response and failure

Every endpoint returns `{decision: bool, context: {decision_id, reason_admin,
policy: {id, version}}}`.

- A deny is HTTP 200 with `decision: false`. Any non-200 status is an error, and
  errors use RFC 9457 problem details.
- **PEPs fail closed** on transport errors, timeouts and any non-200 status. The
  phase 7 adapter makes that decision, not the generated client.
- `policy.version` is the only link from a decision to the policy that produced
  it. The ODRL Policy Repository API does not record what is deployed.
- `reason_admin` is for operators and logs. It is never shown to users, and
  clients must not branch on it.

### Internal evaluation form

Behind the endpoints, every request is normalised into one form (subject, action,
resource(s), context), and that form is written to the audit log. Multi-resource
requests expand into one evaluation per resource. The PDP adapter is the only
component that knows about OPA. Replacing the PDP means replacing the adapter.

### Versioning

The major version is in the path. Within v1 only additive changes are allowed:
new endpoints and new optional fields. Receivers ignore unknown fields. Removing
or retyping a field, or changing multi-resource semantics, needs v2.

Promoting an operation off the privileged-operations endpoint adds an endpoint
and is additive. A PEP still sending the old route gets a 400 and fails closed,
so a promotion must ship in the same release as the updated adapter.

## Phase 7 policy package

`phases/phase7-authz/src/rucio_authz_v6_policy/` keeps `has_permission()` as its
only entry point and becomes an adapter:

```
has_permission(issuer, action, kwargs, session)
  → resolve facts from Rucio's DB        (moved from _owned_scopes / _rule_facts)
  → dispatch on action to a builder      (one per catalogue row; default → privileged)
  → call the generated function          (explicit timeout, reused connection)
  → PermissionResult(decision, reason)   (fail closed on anything but 200)
```

- **Generated code lives in `_generated/`.** CI regenerates it from the
  contract and fails if the result differs from what is committed.
- **The dispatch table and the catalogue must agree.** A known action wrongly
  sent to privileged-operations gets a 400 and denies, so the error is loud.
  A missing builder never silently allows anything.
- **Scope owners.** `is_scope_owner()` answers yes or no, but the contract needs
  the owner. This costs one `scopes` lookup per distinct scope, as today.
  `get_rule()` already returns the rule's `account`, `scope` and `name`.
- **Protocol schemes** are extracted from Rucio's nested parameter dicts, as
  phase 6's `_NESTED_SCHEME_CONTAINERS` does today.
- **Dependencies.** `openapi-python-client` generates the draft cleanly with
  `httpx` and `attrs`. Check both against the Rucio server image pins before
  committing to that generator.

## Equivalence with phase 6

Contract tests reuse phase 6's vectors: each `test_phase6_opa.py` case becomes a
contract request with the same expected decision. The v0 service maps requests
onto the phase 6 OPA input and runs the phase 6 Rego unchanged. After that,
`test_phase6_full_transfer.py` must pass through phase 7.

Deliberate differences, each needing a phase 6 change or a documented test update
first:

| Case | Phase 6 | Contract | Why |
|---|---|---|---|
| `attach_dids_to_dids`, one foreign parent | allowed if *any* attachment scope is owned | denied: every attachment must be permitted | Multi-resource semantics belong to the contract. Fix the Rego in phase 6 first. |
| `add_rule` with empty `dids` | deny | 400, which the PEP treats as deny | `minItems: 1`. Same outcome, earlier. |
| Ownership input | `owned_scopes` | scope owners | The v0 adapter derives `owned_scopes`, so the Rego is unaffected. |
| Unlisted actions | catch-all | `privileged-operations` with the action's name | Same decision, now an explicit route. |

## Security

- TLS everywhere, and PEPs authenticate with client credentials.
- Asserted claims are trusted, so the list of registered PEP clients is part of
  the security boundary and is reviewed like policy.
- Decision logs record the PEP client, subject, token identifiers, operation,
  resources, decision, policy version and `decision_id`. Claim values are logged;
  raw tokens never are.
- Rate limits and payload limits apply per PEP. Set `maxItems` on list fields
  from observed Rucio usage.

## Non-goals

- AuthZEN endpoints (evaluation, batch, search, metadata). They are additive if
  a PEP needs them.
- Typed endpoints for account operations. The trigger is account self-service
  policy, not relevance alone.
- Signed decisions.
- Replacing OPA. The adapter boundary allows it, but this design does not do it.

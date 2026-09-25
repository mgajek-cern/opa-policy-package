# Design-005: Authorization Service API

**Status:** implemented.

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
The phase 7 Rego (`policies/rego/phase7/authz.rego`) has one dispatch line and
one named rule per typed endpoint, and a test keeps the two lists equal.

### On the ADR

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

Every typed endpoint has one dispatch line and one named rule in the phase 7
Rego, and every action the phase 7 Rego knows has a typed endpoint. Operation
names are domain terms, independent of Rucio's action names.

| Operation | Endpoint | Rucio action(s) | Phase 7 rule | Who may | Also checked |
|---|---|---|---|---|---|
| `rule.create` | `POST /v1/decisions/rules/create` | `add_rule` | `_perm_add_rule` | privileged, or owner of every DID scope creating an unlocked rule for itself | RSE expression names |
| `rule.update` | `POST /v1/decisions/rules/update` | `update_rule` | `_perm_update_rule` | privileged, or rule owner who also owns the target scope | no reassignment |
| `rule.delete` | `POST /v1/decisions/rules/delete` | `del_rule` | `_perm_del_rule` | privileged, or rule owner | |
| `did.create` | `POST /v1/decisions/dids/create` | `add_did`, `add_dids` | `_perm_add_did`, `_perm_add_dids` | privileged, or owner of every DID scope | |
| `did.attach` | `POST /v1/decisions/dids/attach` | `attach_dids`, `attach_dids_to_dids` | `_perm_attach_dids`, `_perm_attach_dids_to_dids` | privileged, or owner of every parent scope | |
| `did.detach` | `POST /v1/decisions/dids/detach` | `detach_dids` | `_perm_detach_dids` | privileged, or owner of the parent scope | |
| `rse.create` | `POST /v1/decisions/rses/create` | `add_rse` | `_perm_add_rse` | privileged only | RSE name |
| `rse.update` | `POST /v1/decisions/rses/update` | `update_rse` | `_perm_update_rse` | privileged only | new RSE name, if renamed |
| `rse.delete` | `POST /v1/decisions/rses/delete` | `del_rse` | `_perm_del_rse` | privileged only | |
| `rse.attribute.set` | `POST /v1/decisions/rses/attributes/set` | `add_rse_attribute` | `_perm_add_rse_attribute` | privileged only | |
| `rse.attribute.delete` | `POST /v1/decisions/rses/attributes/delete` | `del_rse_attribute` | `_perm_del_rse_attribute` | privileged only | |
| `protocol.create` | `POST /v1/decisions/protocols/create` | `add_protocol` | `_perm_add_protocol` | privileged only | scheme |
| `protocol.update` | `POST /v1/decisions/protocols/update` | `update_protocol` | `_perm_update_protocol` | privileged only | scheme, if present |
| `protocol.delete` | `POST /v1/decisions/protocols/delete` | `del_protocol` | `_perm_del_protocol` | privileged only | scheme, if present |
| `replica.register` | `POST /v1/decisions/replicas/register` | `add_replicas` | `_perm_add_replicas` | privileged, or owner of every file scope holding a user entitlement | RSE name |
| `replica.delete` | `POST /v1/decisions/replicas/delete` | `delete_replicas` | `_perm_delete_replicas` | privileged, or owner of every file scope holding a user entitlement | |
| *(named)* | `POST /v1/decisions/privileged-operations` | everything else: `add_account`, `add_scope`, `approve_rule`, `update_replicas_states`, ... | catch-all | privileged only | |

The split follows what Rucio records an owner for:

- **RSEs and protocols are privileged only.** The `rses` table has no account
  column, and protocols belong to RSEs, so there is no owner to compare with.
  They are infrastructure, and attributes such as `fts` or `lfn2pfn_algorithm`
  change how data moves.
- **Rules, DIDs and replicas are ownership-gated.** `rules.account` and
  `scopes.account` name owners directly. A replica has no account column; its
  ownership is its DID's, resolved at the scope grain like every other DID
  check (design-003).

Two rules apply:

- **Each operation gets its own request schema, even when the fields are
  identical.** `RseDeleteRequest` and `ReplicaDeleteRequest` look the same
  today. Separate schemas let either one gain fields later without renaming
  another operation's generated model.
- **Operations sharing a Rucio action share an endpoint.** `add_did` and
  `add_dids` both map to `did.create` with a list, and `attach_dids` and
  `attach_dids_to_dids` both map to `did.attach`.

### The privileged-operations endpoint

Rucio's permission layer has many more actions than the Rego lists, and every
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
  endpoint and its own Rego rule in the same change. Once the endpoint exists, the operation's name is rejected on this
  route.

### Request model

**Subject.** `{type, id}`. `type` is `rucio_account` (where `id` is the resolved
account) or `oidc_subject` (where `id` is `sub@iss`, reserved for IAM). `id` and
`type` name the subject for logging and are the only identity available for
credentials that carry no bearer token at all (the root bootstrap). Where a
token is present, the claims the policy reads (`entitlements`, `acr`) come from
that validated token — see Trust model — not from this object; there is no
claims payload in the request body.

**Trust model.** PEPs authenticate with an OAuth2 bearer token, validated
offline by this service (JWKS signature check, `exp`, `aud` scoped to this
service). Subject claims the policy reads are extracted from this validated
token, not taken from the request body. In user-token mode ([ADR-006](../adrs/adr-006-token-exchange-delegated-transfers.md)), the
token is one exchanged (RFC 8693) for this service's audience, carrying
`sub=<user>` and `act=<pep>`, so both subject and caller identity are
independently verifiable. In service-token mode, the token is the PEP's own
client-credentials token, and the policy has only the PEP's identity to decide
on. The `pep:rucio` scope grants access to every endpoint. IAM gets its own
scope when it gets endpoints. Every decision records which PEP presented which
token and which claims were extracted from it.

**Resource facts are supplied by the PEP, as owners.** Requests carry
`scope: {name, owner}` and `rule: {id, owner, target}` rather than phase 6's
`owned_scopes`, which answered "which of these does the caller own?" and so made
half the decision inside the PEP. Sending owners lets the policy compare. Unlike
subject claims, resource facts are never derivable from a token — the service
has no database of its own (see amendment 4) — so they remain PEP-asserted
regardless of token mode.

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

Removing `Subject.properties.token` (see Request model) is a v1→v2 break under
this rule; it ships as v2, or `Token` stays present-but-unused for one
deprecation cycle if a hard break is not wanted yet.

## Implementation

### Phase 7 policy package

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

### Phase 7 Rego

`policies/rego/phase7/authz.rego`, package `vo.authz.v6`, is the phase 6
policy restructured around the contract:

- **One dispatch line and one named rule per typed endpoint action.** No action
  is dispatched through a set difference. Phase 6's shared `_perm_did_action`
  and `_perm_protocol_action` are split per action.
- **`_all_known_actions` equals the set of actions with typed endpoints.**
  `TestContractAlignment` in `tests/test_phase7_opa.py` reads the OpenAPI
  operation ids and OPA's `_all_known_actions`, and fails if they diverge.
- **The input shape is unchanged** (`issuer`, `action`, `token`, `kwargs`), so
  the phase 6 `permission.py` and the v0 service adapter can both drive it.
- **`tests/test_phase7_opa.py` re-runs the phase 6 test classes against it.**
  The replica classes are replaced by ownership cases. It also adds what phase 6
  never had: the three explicit privileged-only RSE rules, `update_rse`,
  `attach_dids` and all three protocol actions.

Before committing, both policies were evaluated side by side over 2,430
decisions: every action, five subject types, and six data-bundle variants
(defaults, RSE allowlist, `required_acr`, custom schemes, replica writes, and an
entitlement bundle). 2,365 were identical, and all 65 differences are the
deliberate changes below:

- 39 DID decisions went from allow to deny (the two DID changes).
- 20 `add_replicas` decisions went from allow to deny: a user entitlement on a
  valid RSE is no longer enough without owned files.
- 6 `delete_replicas` decisions went from deny to allow: users deleting replicas
  of files in scopes they own.

No privileged decision changed. The only admin-entitled subjects among the
differences were admins failing `required_acr`, and those are not privileged.

#### Replica ownership: prerequisite

The Rucio gateway passes only `{rse, rse_id}` to `has_permission` for
`add_replicas` and `delete_replicas`, so today the policy never sees which files
a request touches. Until that changes, the phase 7 Rego denies every
non-privileged replica request, which **breaks user uploads**. Root and admin
paths keep working.

Enabling the ownership path takes two changes, which ship together:

1. **Gateway.** A local patch to `gateway/replica.py` adds the request's `files`
   to the permission kwargs for both actions, the same kind of local patch
   design-004 considers for passing the session through on `del_rule`.
2. **Policy package.** `permission.py` adds `files` to `_PASSTHROUGH_KEYS` and to
   `_SCOPE_CONTAINERS`, so file scopes are forwarded and resolved into
   `owned_scopes` by the same `is_scope_owner()` pass as other DIDs.

The contract requires `files` on both replica requests, so the phase 7 service
adapter cannot build a valid request without the gateway patch. For privileged
callers too, it is a hard prerequisite for phase 7, not an optional extra.

## Testing

### Equivalence with phase 6

Contract tests reuse the phase 7 vectors: each `test_phase7_opa.py` case, which
includes every phase 6 case, becomes a contract request with the same expected
decision. The v0 service maps requests onto the unchanged OPA input shape and
runs the phase 7 Rego. After that,
`test_phase6_full_transfer.py` must pass through phase 7.

Deliberate differences, each needing a phase 6 change or a documented test update
first:

| Case | Phase 6 | Contract | Why |
|---|---|---|---|
| `attach_dids_to_dids`, one foreign parent | allowed if *any* attachment scope is owned | denied: every attachment must be permitted | Multi-resource semantics belong to the contract. Implemented in the phase 7 Rego. |
| `add_dids` or `attach_dids_to_dids` with an owned top-level `scope` | allowed, because the shared DID rule read `kwargs.scope` for every DID action | ignored: each action reads only its own fields | The gateway never sends one, so Rucio behaviour is unchanged. |
| `add_rule` with empty `dids` | deny | 400, which the PEP treats as deny | `minItems: 1`. Same outcome, earlier. |
| Ownership input | `owned_scopes` | scope owners | The v0 adapter derives `owned_scopes`, so the Rego is unaffected. |
| `add_replicas` by a user | user entitlement and a valid RSE name | also every file scope owned | Registering a replica asserts a copy of that DID exists. Requires the gateway patch. |
| `delete_replicas` by a user | denied: privileged only | allowed for the owner of every file scope with a user entitlement | Replicas inherit ownership from their DID. Requires the gateway patch. |
| `update_replicas_states` and unlisted actions | listed privileged-only, or catch-all | `privileged-operations` with the action's name | Same decision, now an explicit route. |

## Non-goals

- AuthZEN endpoints (evaluation, batch, search, metadata). They are additive if
  a PEP needs them.
- Typed endpoints for account operations. The trigger is account self-service
  policy, not relevance alone.
- Signed decisions.
- Replacing OPA. The adapter boundary allows it, but this design does not do it.

## Security

- TLS everywhere, and PEPs authenticate with a bearer token, validated offline
  against the issuer's JWKS on every request.
- Subject claims are extracted from that validated token, not asserted in the
  request body; the list of registered PEP clients (and, in user-token mode,
  the token-exchange audience) is part of the security boundary and is
  reviewed like policy.
- Decision logs record the PEP client, subject, token identifiers, operation,
  resources, decision, policy version and `decision_id`. Claim values are logged;
  raw tokens never are.
- Rate limits and payload limits apply per PEP. Set `maxItems` on list fields
  from observed Rucio usage.

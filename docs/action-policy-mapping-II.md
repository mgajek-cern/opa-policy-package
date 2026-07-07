# Technical Document: Rucio Action Mapping to Authorization Service Operations

## Purpose

This document defines the initial mapping between Rucio permission actions and the higher-level authorization operations exposed by the WP4 Authorization Service.

The Authorization Service exposes **business-oriented authorization operations** through an OpenAPI contract. It does not expose the complete Rucio `has_permission()` action model.

Rucio actions remain internal policy identifiers used only by the Authorization Service when evaluating policies through OPA.

The goal is to provide a stable API contract for DEP components — Rucio directly, and storage endpoints indirectly via their AAI IAM — while keeping OPA, Rego policies and Rucio implementation details internal.

# Authorization Interface

```
POST /v1/authorize
```

## Two request shapes, one contract

The endpoint serves two structurally different questions, from two different direct callers:

* **Rucio (group/scope-centric):** "can this subject perform this operation on this resource" — subject identity comes from Rucio's session/group model. Rucio calls the Authorization Service directly.
* **AAI IAM, on behalf of a storage endpoint (token-centric):** "does this already-introspected token authorize this specific write, right now" — subject identity comes from the token claims IAM just validated (sub, aud, scope). The storage endpoint never calls the Authorization Service itself; it calls IAM for introspection, and IAM calls the Authorization Service as part of that same request handling.

Both shapes populate the same `operation` / `subject` / `resource` / `context` envelope; `subject` simply carries different fields depending on caller.

### Example — Rucio request (existing)

```json
{
  "operation": "rule.create",
  "subject": {
    "id": "alice",
    "groups": ["/atlas/production"]
  },
  "resource": {
    "scope": "alice",
    "sourceRse": "SRC",
    "destinationRse": "DST"
  },
  "context": {
    "protocol": "davs"
  }
}
```

### Example — IAM request on behalf of a storage endpoint (new)

```json
{
  "operation": "transfer.authorize",
  "subject": {
    "id": "alice",
    "token": {
      "sub": "alice",
      "aud": "dst-se.example.org",
      "iss": "https://e-infra-aai.example.org",
      "scope": ["write:MUSICA"]
    }
  },
  "resource": {
    "destinationRse": "DST",
    "path": "/MUSICA/alice/dataset123"
  },
  "context": {
    "protocol": "davs",
    "direction": "destination"
  }
}
```

### Response (unchanged)

```json
{
  "decision": "ALLOW",
  "reason": "scope owner"
}
```

```
business operation
        |
        v
Rucio action(s)  (Rucio requests)
        |
        v
OPA/Rego policy

token claims  (IAM requests, on behalf of storage endpoints)
        |
        v
OPA/Rego policy
```

# Initial Operation Mapping

## Rule Management

**`rule.create`** → `add_rule` (`_perm_add_rule`)
**`rule.update`** → `update_rule`
**`rule.delete`** → `del_rule`

## RSE Management

**`rse.create`** → `add_rse`
**`rse.update`** → `update_rse`

## DID Management

**`did.create`** → `add_did`, `add_dids`
**`did.attach`** → `attach_dids`, `attach_dids_to_dids`
**`did.detach`** → `detach_dids`

## Protocol Management

**`protocol.update`** → `add_protocol`, `update_protocol`, `del_protocol`

Enables future protocol allowlist enforcement through OPA (e.g. `davs`, `s3`, `https`, `root`, `xrdhttp`).

## Transfer Authorization (Phase 5)

**`transfer.create`** (Rucio-originated) → `queue_requests`, `add_rule`
Consumers: Rucio, FTS.

**`transfer.authorize`** (new in this revision)
No direct Rucio action mapping — evaluated against introspected token claims (`subject.token`) rather than Rucio group membership. Direct caller: the AAI IAM serving the relevant storage endpoint (RI SE or e-Infra SE), invoked as part of IAM's own token-introspection flow. The storage endpoint itself never calls this endpoint.

This is a distinct operation from `transfer.create`, not a duplicate: `transfer.create` authorizes *Rucio's* act of queuing a transfer; `transfer.authorize` authorizes the *storage endpoint's* act of accepting a specific inbound/outbound write once a token is presented, via a decision IAM obtains on its behalf. The storage endpoint should not need to know Rucio's internal rule state, and IAM's caller-side integration should not need to know Rucio's action model — that decoupling is the point.

Open question for discussion: should `transfer.authorize` be satisfied purely by re-validating the token/scope against OPA policy, or should the Authorization Service also check that a corresponding `transfer.create` decision was already granted (i.e. cross-reference decisions)? This affects whether the Authorization Service needs any decision-state persistence beyond stateless policy evaluation.

# Not exposed initially

Remain internal Rucio permission checks unless future requirements justify exposure:

* configuration operations
* authentication token operations
* internal daemon operations
* heartbeat management
* low-risk read-only operations

Examples: `set_rse_usage`, `get_next`, `list_heartbeats`, `get_auth_token_x509`.

These do not represent cross-component authorization capabilities and do not require an external API contract.

# API Design Principles

The Authorization Service intentionally does not expose per-action endpoints (`POST /authorize/add_rule`, etc.) because this would couple consumers directly to Rucio internal action names.

```
rule.create              transfer.authorize
      |                          |
      v                          v
  add_rule              (token claims, no Rucio action)
      |                          |
      +----------> OPA/Rego <----+
```

This allows:
* Rucio action names to evolve internally without affecting IAM or FTS-side clients.
* OPA policies to change without impacting consumers.
* Generated OpenAPI clients to remain stable across all direct callers.
* Token-centric and group-centric decisions to share one contract without either leaking into the other.

# Summary Architecture

```
        OpenAPI client                    OpenAPI client
              |                                  |
              v                                  v
           Rucio                          AAI IAM (on behalf of
              |                            storage endpoints, post-
              |                            introspection)
              +---------------> Authorization Service <---------------+
                                       |
                                       v
                                      OPA
                                       |
                                       v
                                     Rego
```

The Authorization Service provides the stable integration boundary for both Rucio's group/scope-centric decisions and IAM's token-centric decisions made on behalf of storage endpoints. Rucio actions remain the internal policy vocabulary for Rucio-originated requests; IAM-originated requests are evaluated directly against introspected token claims. WP4 exposes one smaller, business-oriented operation set suitable for API-first integration and generated client libraries across all direct callers.

---
status: proposed
date: 2026-07-07
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers
informed: DEP component owners
---

# ADR-001: Integrate DEP components with authorization through an API-first Authorization Service, not direct OPA calls

## Context and Problem Statement

DEP components require centralized authorization decisions currently
implemented through Rucio permission checks and OPA policies. The
integration pattern must define whether consumers directly invoke OPA or
integrate through a WP4-owned Authorization Service exposing a stable API
contract.

Consumers are not limited to Rucio: storage endpoints (RI SE, e-Infra SE)
also need authorization decisions before accepting a push or pull. For this
path, the storage endpoint calls its AAI IAM for token introspection, and
the IAM itself — not the storage endpoint — calls the Authorization Service
as part of that flow, returning a combined validity-and-decision result.
Token selection (user vs. service token, per regulatory context) remains
the consumer's responsibility and is outside this integration model.

Storage systems do not provide a uniform authorization extension model
equivalent to Rucio policy packages. Rucio can integrate custom
authorization behaviour through configurable policy logic; storage
technologies such as XRootD instead integrate through token introspection
exposed via their AAI IAM. The authorization architecture needs a stable
integration point that does not require each storage technology to
implement a bespoke OPA integration.

## Decision Drivers

* Decouple consumers from OPA and Rego implementation details.
* Provide a stable integration contract for future DEP components.
* Enable API-first development and generated client libraries.
* Avoid introducing architectural complexity unless justified by
  multi-consumer integration requirements.
* Support future integration of components such as FTS and storage
  services.
* Support heterogeneous Policy Enforcement Point implementations, including
  storage endpoints that enforce decisions obtained via their AAI IAM
  rather than a storage-specific plugin.
* Preserve auditability of the token/subject presented for each decision,
  regardless of consumer.

## Considered Options

1. Direct integration from Rucio/DEP components to OPA.
2. API-first Authorization Service owned by WP4, internally integrating
   with OPA.

## Decision Outcome

Chosen option: **2. API-first Authorization Service owned by WP4**, because
OPA's `input` document has no versioned, tool-generated client contract —
its shape is an implementation detail of the current policy, not a designed
interface — so a stable generated client is only possible against a
contract designed to remain stable.

Rucio and the AAI IAM (on behalf of storage endpoints) integrate with the
service through a versioned OpenAPI specification. The service internally
translates requests into OPA evaluations. FTS is not a direct consumer at
this phase; authorization for FTS-orchestrated transfers is covered by the
two PEPs already defined (Rucio, and the storage endpoint via IAM).
Extending direct integration to FTS is out of scope here.

The service is deliberately PDP-agnostic: OPA is today's Policy Decision
Point, not a permanent commitment, because the contract models
authorization concepts rather than OPA/Rego specifics. The contract models
operation, subject, resource and context independently of any
consumer-specific or OPA-specific representation, and does not accept or
forward opaque per-consumer payloads (e.g. a `rucio_input` passthrough
field) — doing so would reduce the service to a façade over OPA.

### Positive Consequences

* Consumers are independent of OPA, Rego structure and policy input
  formats.
* OpenAPI enables generated client libraries and consistent integration.
* Policy implementation can evolve while consumer integrations stay
  compatible, provided the contract remains stable.
* Centralized handling of auditing, logging, validation, caching and policy
  context enrichment.
* Enables reuse by future DEP services, including storage endpoints acting
  as PEPs via their AAI IAM.
* Enables centralized decision logging correlated with the subject/token
  context each consumer supplies.

### Negative Consequences

* Additional service component to operate.
* Additional network hop for authorization decisions.
* Requires maintaining an API contract.
* Requires the contract to accommodate at least two distinct request
  shapes: Rucio's group/scope-centric requests, and IAM's token-centric
  requests on behalf of storage endpoints.

## Confirmation

Compliance is confirmed by:

* Rucio and the AAI IAM using generated clients from the service's OpenAPI
  specification.
* No direct OPA endpoint usage outside the Authorization Service.
* IAM's token introspection and its Authorization Service call executed as
  one flow but logged as distinct steps.
* Integration tests validating decisions against OPA policies, for both
  Rucio-originated and IAM-originated requests.

## Pros and Cons of the Options

### 1. Direct integration with OPA

* Good, because it has minimal architectural overhead.
* Good, because it allows rapid policy experimentation.
* Good, because the existing Rucio policy package model already supports
  this pattern.
* Neutral, because OPA input structures can represent rich ABAC decisions.
* Bad, because OPA becomes part of the public integration contract.
* Bad, because consumers must understand Rego-oriented input structures.
* Bad, because changes to policy input models require coordinated client
  changes.
* Bad, because auditing, caching and context enrichment are duplicated
  across clients.
* Bad, because OPA's `input` document has no versioned, tool-generated
  client contract — every direct caller, including IAM, would hand-build
  Rego-shaped requests.

### 2. WP4 Authorization Service with OpenAPI contract

* Good, because the API contract is stable and versioned.
* Good, because generated clients reduce integration errors.
* Good, because consumers are decoupled from OPA-specific representation,
  reducing coupling to the current policy evaluation technology.
* Good, because policy-related concerns are centralized.
* Good, because the same capability can serve multiple systems: Rucio
  directly, and storage endpoints as PEPs via their AAI IAM.
* Good, because IAM's introspection and its Authorization Service call
  remain separately logged despite executing as one flow.
* Bad, because it introduces another deployable component.
* Bad, because it adds a small amount of latency.

## Implementation notes (non-normative)

```
Rucio / IAM (on behalf of Storage Endpoint)
          |
          | OpenAPI client
          |
Authorization Service
          |
          OPA
```

See [design-005](../design/design-005-authorization-service-api.md) for the
contract itself and [design-006](../design/design-006-authorization-service-implementation.md)
for how the service is built.

---
status: proposed
date: 2026-07-07
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers
informed: DEP component owners
---
# API-first Authorization Service vs Direct OPA Integration

## Context and Problem Statement

DEP components require centralized authorization decisions currently implemented through Rucio permission checks and OPA policies. The integration pattern must define whether consumers directly invoke OPA or integrate through a WP4-owned Authorization Service exposing a stable API contract.

The decision concerns the interface boundary between DEP components and the authorization layer. Consumers are not limited to Rucio: storage endpoints (RI SE, e-Infra SE) also need authorization decisions before accepting a push or pull. For this path, the storage endpoint calls its AAI IAM for token introspection, and the IAM itself — not the storage endpoint — calls the Authorization Service as part of that flow, returning a combined validity-and-decision result to the storage endpoint. Token selection (user vs. service token, per regulatory context such as GDPR or FDA) remains the responsibility of the consumer and is outside the Authorization Service integration model; the service consumes whatever subject/token context a request presents.

Storage systems do not provide a uniform authorization extension model equivalent to Rucio policy packages. While Rucio can integrate custom authorization behaviour through configurable policy logic, storage technologies such as XRootD are expected to integrate through token introspection capabilities exposed via their AAI IAM rather than through storage-specific authorization plugins. The authorization architecture therefore needs to provide a stable integration point that does not require each storage technology to implement a bespoke OPA integration.

## Decision Drivers

* Decouple consumers from OPA and Rego implementation details.
* Provide a stable integration contract for future DEP components.
* Enable API-first development and generated client libraries.
* Avoid introducing architectural complexity unless justified by multi-consumer integration requirements.
* Support future integration of components such as FTS and storage services.
* Support heterogeneous Policy Enforcement Point implementations, including storage endpoints that enforce authorization decisions obtained through their AAI IAM integration path rather than through a storage-specific authorization plugin.
* Preserve auditability of the token/subject presented for each decision, regardless of consumer.

## Considered Options

1. Direct integration from Rucio/DEP components to OPA.
2. API-first Authorization Service owned by WP4, internally integrating with OPA.

## Decision Outcome

Chosen option: **API-first Authorization Service owned by WP4**

Rucio and the AAI IAM (on behalf of storage endpoints) shall integrate with a WP4-owned Authorization Service through a versioned API specification (OpenAPI). The Authorization Service shall internally translate requests into OPA policy evaluation requests.

FTS remains a DEP component but is not a direct consumer of the Authorization Service at this phase — it is not a Policy Enforcement Point in this decision. Authorization for FTS-orchestrated transfers is covered by the two PEPs already defined: Rucio (`rule.create`/`transfer.create`) and the storage endpoint (`transfer.authorize`, obtained via IAM). Extending direct Authorization Service integration to FTS is out of scope for this ADR and can be revisited as a separate decision if a future requirement calls for it.

OPA remains the current policy evaluation engine; however, its interfaces are treated as internal implementation details rather than consumer-facing contracts. For the storage path, token introspection and the authorization decision are both handled by IAM as one flow on the storage endpoint's behalf, but remain two distinct, distinctly logged operations against two distinct systems (IAM's own introspection, and IAM's call to the Authorization Service) — not a single combined check.

A structural reason Option 2 is preferable, beyond decoupling: OPA's REST API accepts an arbitrary `input` document per Rego package, with no standard, versioned schema suitable for OpenAPI client generation. Rego has no ecosystem convention analogous to an OpenAPI contract — its input shape is an implementation detail of the current policy, not a designed interface. A stable, generated client is only possible against a contract designed to remain stable, which is what the Authorization Service provides and direct OPA access does not.

The API contract shall model authorization concepts (operation, subject, resource, context) independently of any consumer-specific or OPA-specific representation. It shall not accept or forward opaque per-consumer payloads (e.g. a `rucio_input` passthrough field) — doing so would reduce the Authorization Service to a façade over OPA and defeat the purpose of this decision.

## Consequences

### Positive

* Consumers are independent of OPA, Rego structure and policy input formats.
* OpenAPI enables generated client libraries and consistent integration.
* Authorization policy implementation can evolve while maintaining compatibility with consumer integrations, provided the Authorization Service contract remains stable.
* Centralized handling of auditing, logging, validation, caching and policy context enrichment.
* Enables reuse by future DEP services — concretely, by storage endpoints acting as PEPs via their AAI IAM, not only by Rucio.
* Enables centralized authorization decision logging and consistent correlation of decisions with the subject/token context supplied by consumers (exact audit storage, retention and ownership to be defined separately).

### Negative

* Additional service component to operate.
* Additional network hop for authorization decisions.
* Requires maintaining an API contract.
* Requires the API contract to accommodate at least two distinct request shapes: Rucio's group/scope-centric requests, and IAM's token-centric requests made on behalf of storage endpoints (see action mapping doc).

## Confirmation

Compliance is confirmed by:
* Rucio and the AAI IAM using generated clients from the Authorization Service OpenAPI specification.
* No direct OPA endpoint usage outside the Authorization Service.
* IAM's token introspection and its Authorization Service call are executed as one flow but logged as distinct steps.
* Integration tests validating Authorization Service decisions against OPA policies, for both Rucio-originated and IAM-originated requests.

# Pros and Cons of the Options

## Option 1: Direct Integration with OPA

DEP components construct OPA input documents and call the OPA REST API directly.

Example:
```
Rucio / IAM (on behalf of Storage Endpoint)
  |
  | POST /v1/data/.../allow
  |
OPA
```

### Pros
* Good, because it has minimal architectural overhead.
* Good, because it allows rapid policy experimentation.
* Good, because the existing Rucio policy package model already supports this pattern.
* Neutral, because OPA input structures can represent rich ABAC decisions.

### Cons
* Bad, because OPA becomes part of the public integration contract.
* Bad, because consumers must understand Rego-oriented input structures.
* Bad, because changes to policy input models require coordinated client changes.
* Bad, because auditing, caching and context enrichment are duplicated across clients.
* Bad, because OPA's `input` document has no versioned, tool-generated client contract — every direct caller, including IAM, would hand-build Rego-shaped requests.
* Bad, because direct OPA integration assumes every consumer can host and maintain authorization integration logic. This is not true for all DEP components, particularly storage technologies that expose token introspection integration through IAM rather than a Rucio-like authorization plugin model.

## Option 2: WP4 Authorization Service with OpenAPI Contract

Rucio, and the AAI IAM on behalf of storage endpoints, call a dedicated authorization API. The service invokes OPA internally. FTS itself is not a direct caller (see Decision Outcome).

Example:
```
Rucio / IAM (on behalf of Storage Endpoint)
          |
          | OpenAPI client
          |
Authorization Service
          |
          |
          OPA
```

### Pros
* Good, because the API contract is stable and versioned.
* Good, because generated clients reduce integration errors.
* Good, because consumers are decoupled from OPA-specific APIs and policy representation details, reducing coupling to the current policy evaluation technology.
* Good, because policy-related concerns are centralized.
* Good, because the same authorization capability can serve multiple systems: Rucio directly, and storage endpoints as PEPs via their AAI IAM.
* Good, because IAM's token introspection and its call to the Authorization Service, though executed as one flow, remain separately logged, aiding audit clarity.

### Cons
* Bad, because it introduces another deployable component.
* Bad, because it adds a small amount of latency.

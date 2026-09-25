---
status: proposed
date: 2026-09-17
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers
informed: DEP component owners
---

# ADR-004: Build the Authorization Service on ports-and-adapters, with integration tests authoritative and OpenTelemetry for observability

## Context and Problem Statement

[ADR-001](./adr-001-authz-service.md) establishes a WP4-owned Authorization
Service in front of OPA; [design-005](../design/design-005-authorization-service-api.md)
defines its contract. This ADR records how the service is built and why —
its architecture, stack, testing strategy and telemetry — and the
properties that must not change by accident.

The service is small by nature. Policy lives in Rego, and resource facts
are resolved by the PEP. The service maps a typed request onto the PDP's
input, calls the PDP, fails closed, and records the decision. It keeps no
state. Detailed layout, tooling versions, telemetry names, test fixtures,
conformance checks and rollout sequencing are in
[design-006](../design/design-006-authorization-service-implementation.md).

## Decision Drivers

* Reuse the existing Python work in the policy packages and their tests.
* Keep the PDP replaceable through a real seam, as ADR-001 requires, rather
  than by convention.
* Keep the structure proportionate to a thin, stateless service.
* Establish correctness against the real policy, which only a real PDP can
  execute.
* Make every decision observable and auditable without the service owning
  storage.
* The PEP client must run inside Rucio's Python 3.9 runtime.

## Considered Options

**Architecture**
1. Plain layered application: routes call the PDP directly.
2. Clean Architecture: dependencies point inward, divided into prescribed
   boundaries (entities, use cases, interface adapters).
3. Ports and adapters (hexagonal): dependencies point inward too, but only
   the boundary between the core and the outside world is prescribed.

**Testing**
- A. Unit tests with a mocked PDP as the primary suite.
- B. Integration tests against the real PDP only.
- C. Integration tests authoritative, plus unit tests restricted to pure
  logic.

**Telemetry**
- I. Framework logging plus a separate metrics library.
- II. OpenTelemetry for traces, metrics and logs.

## Decision Outcome

Chosen: **3. Ports and adapters**, **C. Integration tests authoritative**,
and **II. OpenTelemetry**, implemented in **Python with FastAPI** and API
models generated from the contract, because this combination reuses
existing Python work, keeps the PDP genuinely replaceable rather than
replaceable by convention, and ties correctness to the real policy rather
than to assumptions encoded in a mock.

A decision core owns the domain model and fail-closed handling and defines
a PDP port; HTTP is the inbound adapter and OPA the outbound one. A change
is correct when integration tests pass against the real PDP running the
real policy; unit tests are allowed only for pure logic. Traces and metrics
go out through OpenTelemetry; each decision emits one audit record, kept
separate from application logs. The service persists nothing.

### Invariants

These are the durable part of this decision. Tooling, versions and
configuration may change without a new ADR. These may not.

* **Fail closed.** A PEP never receives a permit that results from a PDP
  failure. Only an explicit permit from the PDP produces a permit.
* **Alignment.** The contract's operations, the service's routes and
  catalogue, the PEP client and the policy's known actions stay identical.
* **Dependency direction.** The core never depends on adapters, the web
  framework or telemetry exporters.
* **Audit data boundary.** Subject and resource information leaves the
  service only in audit records, never in application logs, span
  attributes or metrics, and raw tokens are never emitted.

### Positive Consequences

* The PDP can be replaced behind its port, provided the new PDP reproduces
  the contract's decisions.
* Passing tests mean the service, the mapping and the policy agree.
* Decisions are traceable end to end without a database.
* Existing Python work and test vectors carry over.
* The core can grow towards Clean Architecture's inner structure when
  there is logic to justify it, without changing the boundary.

### Negative Consequences

* Integration tests need Docker, and feedback is slower than with unit
  tests.
* Supporting Python 3.9 ties the PEP client to an older generator until
  Rucio's runtime is upgraded.
* Audit records identify the subject and the resources accessed, so the
  telemetry backend falls under data-protection governance. Which
  identifiers are recorded, and whether they are pseudonymised, is decided
  in design-006.

## Confirmation

Each invariant has an automated check that runs in CI. The checks and how
they run are defined in design-006, under "Conformance checks." This ADR
is confirmed when every invariant has a check and all checks pass.

## Pros and Cons of the Options

### 1. Plain layered application

* Good, because it is the least code.
* Bad, because the PDP's input shape and client leak into the routes, so
  the seam exists only by convention.

### 2. Clean Architecture

* Good, because its dependency rule provides the same PDP independence.
* Bad, because it prescribes inner boundaries (input boundaries, use-case
  interactors, request/response models per operation) that currently have
  no responsibilities in a thin, stateless service.
* Neutral, because those boundaries can still be introduced later if the
  core gains substantial domain logic.

### 3. Ports and adapters (chosen)

* Good, because the one boundary that matters, the PDP, is an explicit
  port.
* Good, because the core's internal structure can follow its actual
  complexity, ending close to option 2 if that complexity arrives.
* Bad, because the dependency rule must be enforced by tooling.

### A. Unit tests with a mocked PDP

* Good, because feedback is fast and needs no containers.
* Bad, because a mock asserts what the service sends, not what the policy
  decides.

### B. Integration tests only

* Good, because every test proves a real decision.
* Bad, because pure logic can only be diagnosed through a wrong decision.

### C. Integration tests authoritative, plus unit tests for pure logic (chosen)

* Good, because it keeps B's guarantee and adds precise failures for pure
  logic.
* Bad, because the "pure logic" boundary needs enforcing.

### I. Framework logging and a metrics library

* Good, because it is simple.
* Bad, because signals cannot be correlated across Rucio, the service and
  OPA.

### II. OpenTelemetry (chosen)

* Good, because one vendor-neutral mechanism carries all signals and
  correlates them.
* Bad, because it adds dependencies and configuration.

## Implementation notes (non-normative)

```mermaid
flowchart LR
    PEP["Rucio PEP"] -->|HTTP| In["HTTP adapter"]
    subgraph Core
        DS["Decision logic<br/>catalogue, fail closed"] --> PP[["PDP port"]]
    end
    In --> DS
    OPAAd["OPA adapter"] -. implements .-> PP
    OPAAd --> OPA[("OPA")]
```

Option 2 (Clean Architecture) shown for comparison, without a presenter or
view model:

```mermaid
flowchart LR
    PEP["Rucio PEP"] -->|HTTP| Ctrl["Controller"]
    subgraph Core
        IB[["Input boundary"]] --> UC["Use-case interactor"]
        UC --> Ent["Entities"]
        UC --> GW[["PDP gateway"]]
    end
    Ctrl --> IB
    UC -->|response model| Ctrl
    OPAGW["OPA gateway"] -. implements .-> GW
    OPAGW --> OPA[("OPA")]
```

Full layout, versions, telemetry field lists and rollout sequencing are in
design-006, not duplicated here.

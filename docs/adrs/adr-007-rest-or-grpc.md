---
status: proposed
date: 2026-09-24
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers, DEP operations, authz-service maintainers
informed: DEP component owners, PEP implementers
---

# Wire protocol for the Authorization Service: REST/JSON vs gRPC/protobuf

## Context and Problem Statement

The Authorization Service is called on every Rucio `has_permission()`
check — internal-only, no external consumers. Contract is currently
REST/JSON ([api/openapi.yaml](../../services/authorization-service/api/openapi.yaml)).
Should it stay REST/JSON, or move to gRPC/protobuf?

## Decision Drivers

* PEPs bind to whatever ships first; a later transport change breaks
  every caller, not just an internal refactor.
* The typed-endpoint routes, the 400-collision check, and
  `known_actions()` all assume HTTP status codes as decision
  signals — gRPC needs its own error-mapping scheme.
* No consumer beyond Rucio's Python PEP exists, and no latency
  bottleneck has been measured.

## Considered Options

1. Keep REST/JSON.
2. Adopt gRPC/protobuf.
3. Offer both, always on.

## Decision Outcome

Chosen: **1. Keep REST/JSON.**

No measured bottleneck points at JSON serialization over network/OPA
round-trip time, and no non-Python consumer exists to make protobuf's
cross-language codegen worth it yet. REST/JSON keeps `curl`/`httpx`
debuggability and lets `openapi.yaml` double as documentation, at no
cost over an already-built, tested (111 passing) surface.

A default, not a closed question — see "What would change the answer."

### Consequences

* Good: no migration risk on an already-stable, tested contract.
* Good: debugging stays one `curl` away.
* Bad: if load or a second-language consumer materializes, the switch
  is then a breaking change for every PEP — the cost is deferred, not
  eliminated.

## Pros and Cons of the Options

### 1. Keep REST/JSON

* Good: already built, tested, debuggable with standard HTTP tooling.
* Bad: JSON/HTTP overhead is strictly higher-cost than protobuf/HTTP2
  at this call volume, though unmeasured against the real bottleneck.

### 2. Adopt gRPC/protobuf

* Good: smaller payloads, HTTP/2 multiplexing, strongly-typed
  generated clients.
* Bad: needs a new error-mapping scheme (no status codes to lean on),
  and `curl`-based debugging needs `grpcurl` or generated clients.

### 3. Offer both

* Good: `core/ports.py`'s `PolicyDecisionPoint` is already
  framework-agnostic — this is an added adapter, not a rewrite.
* Bad: doubles the surface (two contracts, two codegen pipelines) for
  a benefit that only exists once a second consumer or a measured
  bottleneck justifies it.

## What would change the answer

* A measured bottleneck traced specifically to JSON serialization, not
  network/OPA round-trip time.
* A second, non-Python PEP consumer.

## Not decided here

Offering both transports — always-on, or selected per deployment via a
settings flag — isn't ruled out, only deferred. Either warrants its
own ADR if one of the above conditions is met.

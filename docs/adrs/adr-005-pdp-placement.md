---
status: proposed
date: 2026-09-17
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers, DEP operations
informed: DEP component owners
---
# ADR-005: Co-locate the Authorization Service and PDP in the same network as the PEPs

## Context and Problem Statement

Every request a PEP gates waits synchronously for a decision from the
Authorization Service and its PDP ([ADR-001](./adr-001-authz-service.md),
[ADR-004](./adr-004-authorization-service-implementation.md)). PEPs fail closed,
so a slow or unreachable PDP fails the requests it gates. Should the service and
its PDP run next to the PEPs, or outside their network?

## Decision Drivers

* Latency on every gated request.
* Availability: with fail-closed PEPs, a PDP outage is an application outage.
* Decision traffic carries personal and confidential data.
* Operational effort.
* Consumers outside the PEPs' network must still obtain decisions.

## Considered Options

1. Outside the PEPs' network, as a remote shared service.
2. In the same network as the PEPs, with the PDP co-located with the service.
3. Embedded alongside every PEP instance.

## Decision Outcome

Chosen: **2. In the same network as the PEPs, with the PDP co-located.**

Decisions stay within the network where they are needed, and the PDP is reachable
only by the service. Policy management does not have to be local: policies can be
distributed asynchronously, so an outage in that path delays policy updates but
does not block decisions. External consumers reach the service through a single
authenticated entry point.

### Positive Consequences

* Latency is low and predictable, and decision traffic stays within
  the network.
* The PDP shares the fate of the applications it serves, not of an
  external network.

### Negative Consequences

* Every network that hosts PEPs needs its own deployment and policy
  distribution.
* External consumers depend on the entry point's availability.

## Confirmation

Compliance is confirmed by:

* The Authorization Service and its PDP are deployed within the same
  network segment as the PEPs they serve, not reachable only over an
  external network.
* External consumers reach the service through the single authenticated
  entry point, not directly to the PDP.
* Policy distribution to the co-located PDP is asynchronous and does not
  block in-flight decisions during an update.

## Pros and Cons of the Options

### 1. Remote shared service

* Good, because a single deployment serves every site.
* Bad, because every decision crosses an external network, adding latency, a
  failure mode and data exposure.

### 2. Same network, co-located PDP

* Good, because it combines local latency with one deployment per network.
* Bad, because multi-network setups need a deployment in each.

### 3. Embedded per PEP instance

* Good, because it has the lowest latency.
* Bad, because instances multiply, their upgrades are tied to each application's
  releases, and external consumers have no shared endpoint.

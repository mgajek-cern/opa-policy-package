---
status: proposed
date: 2026-07-08
decision-makers: WP4, DEP architecture team
consulted: RI/e-Infra storage operators, DEP component owners
informed: Rucio policy package maintainers
---
# OPA/Authorization Service Deployment Topology: Sidecar, Sidecarless (Ambient Mesh), or Plain Direct Integration

## Context and Problem Statement

The Authorization Service ADR (adr-authorization-service.md) decided *who calls what* (Rucio and IAM call the Authorization Service; the Authorization Service calls OPA). This ADR concerns a separate question: *how is that call physically deployed*, and specifically, who owns cross-cutting concerns like mTLS, authn/authz enforcement, and observability for these calls — infrastructure (via a service mesh, sidecar or ambient) or each consumer individually.

"Sidecarless" is not synonymous with "no infrastructure-provided middleware" — ambient mesh (e.g. Istio Ambient, Cilium mesh) is itself a sidecarless pattern that still provides infrastructure-owned mTLS/authn/observability, just via a shared per-node proxy instead of a per-pod one. That is a distinct option from plain direct integration, where no mesh is involved at all and each consumer handles these concerns itself. This ADR treats them as three separate options rather than two.

This matters because consumers span different operational realities: DEP-managed components (Rucio, and potentially FTS) may run cloud-natively, possibly on a shared, mesh-capable cluster; RI/e-Infra storage endpoints most likely do not run cloud-natively, do not expose a plugin/extension mechanism, and integrate only via a token-introspection hook toward IAM (see credential registry and flow diagrams docs) — ruling out both sidecar and ambient mesh for them regardless of which option wins for cluster-resident consumers. **This assumption about storage endpoint deployment is not yet confirmed and needs validation with RI/e-Infra operators before this decision is finalized.**

## Decision Drivers

* Minimize per-call latency where it matters (high-frequency authorization checks).
* Avoid imposing a deployment model (Kubernetes control/data plane, mesh membership) on components that cannot support it.
* Where a unified ownership of authn, authz enforcement, mTLS, and observability is achievable, prefer infrastructure-owned middleware over each consumer reimplementing these concerns individually.
* Keep the integration pattern uniform enough to avoid maintaining divergent client implementations across too many topologies.
* Match the [Authorization Service ADR's](adr-001-authz-service.md) existing centralization choice rather than reopening it.

## Considered Options

1. **Sidecar**: a proxy (or OPA itself) co-located per-pod with each consumer, typically injected as a Kubernetes sidecar container. mTLS, authn/authz, and observability are infrastructure-owned but duplicated per pod.
2. **Sidecarless / ambient mesh**: the same infrastructure-owned middleware (mTLS, authn/authz enforcement, observability) as sidecar mode, but provided by a shared per-node proxy (e.g. Istio Ambient, Cilium mesh) instead of a per-pod one — lower resource overhead, same unified ownership, still requires cluster membership and mesh tooling. Only viable for consumers that are themselves cluster-resident.
3. **Plain direct integration (no mesh)**: consumers call the Authorization Service as an ordinary networked API. No infrastructure-provided mTLS/authn/observability layer — those concerns are each consumer's or the Authorization Service's own responsibility. Works regardless of the consumer's deployment model or cluster membership.

## Decision Outcome

Chosen option: **Plain direct integration as the current baseline**

All consumers — Rucio and IAM alike — integrate with the Authorization Service as a plain networked OpenAPI call, with no service-mesh layer assumed. This requires no additional infrastructure per consumer and is the only option available to RI/e-Infra storage endpoints under the current (unconfirmed) assumption that they are neither cloud-native nor cluster-resident.

Sidecar and ambient-mesh are deliberately not adopted now, not because they're inferior in principle — ambient mesh in particular is a legitimate way to get infrastructure-owned mTLS/authn/observability without per-pod sidecar overhead — but because they only benefit consumers that share a mesh-enabled cluster, and no such shared cluster membership across DEP components is confirmed yet. If DEP components (Rucio, and any future cloud-native services) later share a mesh-enabled cluster, ambient mesh is worth revisiting ahead of classic per-pod sidecars, since it gives the same unified ownership of these concerns at lower operational cost. This is left open rather than decided now.

## Consequences

### Positive
* No new infrastructure dependency introduced beyond the Authorization Service itself.
* Works uniformly for consumers regardless of deployment model or cluster membership, including non-cloud-native storage endpoints.
* Consistent with the centralization already decided in the Authorization Service ADR — no divergent integration path to maintain.

### Negative
* Every authorization check incurs a full network round trip; no local/co-located or node-level fast path.
* mTLS, authn, and observability for these calls are each consumer's own responsibility rather than infrastructure-owned — more to specify and audit per consumer, with more room for inconsistency across them.

## Open Points

* **Confirm actual deployment model of RI/e-Infra storage endpoints** (containerized, Kubernetes, VM/bare-metal) and whether any DEP components share a common mesh-enabled cluster — this determines whether sidecar/ambient mesh are real future options for any consumer, or off the table entirely.
* If any DEP component later requires infrastructure-owned mTLS/authn/observability or sidecar-level latency, evaluate ambient mesh (node-level, lower overhead) ahead of classic per-pod sidecars, and weigh both against simply hardening the plain-integration path first (mutual TLS at the application layer, connection reuse, caching).

## Confirmation

Compliance is confirmed by:
* No consumer requires a co-located OPA/mesh process or cluster/mesh membership to function.
* Storage endpoint integration is validated against their actual (not assumed) deployment model before this ADR is marked accepted.
* Any future move to sidecar or ambient mesh for a subset of consumers is recorded as an amendment here, not a silent topology change.

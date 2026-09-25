---
status: proposed
date: 2026-09-21
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers, DEP operations, FTS3/storage operators
informed: DEP component owners
---

# ADR-006: Use RFC 8693 token exchange with an `act` claim for delegated transfers

## Context and Problem Statement

Rucio (Conveyor) submits transfer jobs to FTS3, which presents a bearer
token to destination storage to authorize third-party copies. Separately,
authz-service accepts requests from PEPs and trusts PEP-asserted subject
claims without verifying the caller ([design-005](../design/design-005-authorization-service-api.md)).
Both are instances of one problem: a service acting on a user's behalf
needs to prove who it's acting for and that it's the one acting, to a
downstream verifier that only sees the token. Which token shape carries
both facts?

## Decision Drivers

* The downstream verifier (storage, authz-service) must be able to make
  per-user decisions, not just per-service ones.
* A leaked or replayed token must be distinguishable from the user calling
  directly.
* Some VOs (EGI) require real user identity at the resource; others (CMS,
  ATLAS) run service-identity-only and must keep doing so.
* Rucio must survive submission happening well after the original request
  (retries, async scheduling).

## Considered Options

1. Enrich service token — Rucio's own token, user claim carried as
   metadata.
2. True user-subject token — mint a plain user token at submission time.
3. Token exchange (RFC 8693) with an `act` claim.

## Decision Outcome

Chosen: **3. Token exchange with an `act` claim**, because it is the only
option where the downstream verifier gets a verified per-user identity and
a verified delegation record in one token, rather than an unverified
side-channel claim (option 1) or a delegation record lost entirely
(option 2).

The resulting token carries `sub=<user>` and `act=<rucio>`. Audience
restriction is native to exchange — a token minted for one downstream `aud`
does not work against another — so this generalizes to every Rucio-to-
downstream hop, including PEP authentication into authz-service, without a
new scheme per hop.

Deployments that want service-identity-only (CMS, ATLAS) select
**service-token mode** via a feature flag; EGI and similar select
**user-token mode** (this option). The two modes are configured per
deployment, not negotiated per request, and neither falls back to the
other silently — exchange failure in user-token mode fails the transfer
closed.

### Positive Consequences

* One validated token answers both "who is this for" and "who vouched for
  it."
* Audience restriction bounds blast radius on leak, natively.
* One mechanism reused across Rucio→storage and PEP→authz-service, not a
  bespoke scheme per boundary.

### Negative Consequences

* Rucio must persist user refresh tokens across the gap between request
  and submission/retry — new state that didn't exist before.
* A retry after refresh-token expiry/revocation fails closed and surfaces
  as a user-visible re-auth requirement — a real UX cost service-token
  mode doesn't have.

## Confirmation

Compliance is confirmed by:

* A downstream verifier (storage, authz-service) can independently confirm
  both `sub` and `act` from one presented token, without a side-channel
  claim.
* User-token mode deployments fail transfers closed, not open, on exchange
  or refresh failure.
* Service-token mode deployments (CMS, ATLAS) show no behavior change from
  before this decision.
* Integration tests exercise both modes against a real token-exchange
  endpoint.

## Pros and Cons of the Options

### 1. Enrich service token

* Good, because no refresh-token persistence is needed.
* Bad, because storage sees `sub=rucio` only; the user claim is an
  unverified audit hint, not an authorization input — the confused-deputy
  gap this ADR exists to close.

### 2. True user-subject token

* Good, because storage sees real per-user identity.
* Bad, because nothing distinguishes "Rucio relayed this" from "the user
  called storage directly" — a replayed token is indistinguishable from a
  legitimate direct call.
* Bad, because it needs the same refresh-token persistence as option 3,
  for strictly less information.

### 3. Token exchange with `act` (chosen)

* Good, because it carries both subject and actor, audience-restricted, in
  one token.
* Bad, because it requires refresh-token persistence and a new store to
  hold it.

## Implementation notes (non-normative)

As implemented (2026-09-21), refresh tokens are stored as additional
columns (`refresh_token`, `refresh_expired_at`, `refresh_lifetime`,
`refresh_start`) on the existing `models.Token` row, alongside the access
token, in `authentication.py`'s `__save_validated_token()` — not in a
separate table as the Decision Outcome above might otherwise imply. This
note exists so the ADR's decision-level claim ("Rucio must persist user
refresh tokens") isn't read as also fixing the storage shape; the shape is
an implementation detail tracked here, not decided by this ADR.

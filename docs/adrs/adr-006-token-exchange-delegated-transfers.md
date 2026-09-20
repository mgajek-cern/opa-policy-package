---
status: proposed
date: 2026-09-21
decision-makers: WP4, DEP architecture team
consulted: Rucio policy package maintainers, DEP operations, FTS3/storage operators
informed: DEP component owners
---

# Token strategy for delegated transfers

## Context and Problem Statement

Rucio (Conveyor) submits transfer jobs to FTS3, which presents a bearer token to destination storage to authorize third-party copies. Separately, authz-service accepts requests from PEPs and trusts PEP-asserted subject claims without verifying the caller ([design-005](../design/design-005-authorization-service-api.md)). Both are instances of one problem: a service acting on a user's behalf needs to prove *who it's acting for* and *that it's the one acting*, to a downstream verifier that only sees the token.

Which token shape carries both facts?

## Decision Drivers

* The downstream verifier (storage, authz-service) must be able to make per-user decisions, not just per-service ones.
* A leaked or replayed token must be distinguishable from the user calling directly.
* Some VOs (EGI) require real user identity at the resource; others (CMS, ATLAS) run service-identity-only and must keep doing so.
* Rucio must survive submission happening well after the original request (retries, async scheduling).

## Considered Options

1. Enrich service token — Rucio's own token, user claim carried as metadata.
2. True user-subject token — mint a plain user token at submission time.
3. Token exchange (RFC 8693) with an `act` claim.

## Decision Outcome

Chosen: **3. Token exchange with an `act` claim.**

The resulting token carries `sub=<user>` and `act=<rucio>` in one place: the downstream verifier gets real per-user authorization *and* a verifiable record of who relayed the request, without trusting an unverified side-channel claim (option 1) or losing the delegation record entirely (option 2). Audience restriction is native to exchange — a token minted for one downstream `aud` doesn't work against another — so this generalizes to every Rucio-to-downstream hop, including PEP authentication into authz-service, without a new scheme per hop.

Deployments that want service-identity-only (CMS, ATLAS) select **service-token mode** via a feature flag; EGI and similar select **user-token mode** (this option). The two modes are configured per deployment, not negotiated per request, and neither falls back to the other silently — exchange failure in user-token mode fails the transfer closed.

### Consequences

* Good, because one validated token answers both "who is this for" and "who vouched for it."
* Good, because audience restriction bounds blast radius on leak, natively.
* Good, because it's one mechanism reused across Rucio→storage and PEP→authz-service, not a bespoke scheme per boundary.
* Bad, because Rucio must persist user refresh tokens across the gap between request and submission/retry — new state that didn't exist before.
  **Implementation note (2026-09-21):** refresh tokens are stored as
  additional columns (`refresh_token`, `refresh_expired_at`,
  `refresh_lifetime`, `refresh_start`) on the existing `models.Token`
  row, alongside the access token, in `authentication.py`'s
  `__save_validated_token()` — not in a separate table as originally
  decided here.
* Bad, because a retry after refresh-token expiry/revocation fails closed and surfaces as a user-visible re-auth requirement — a real UX cost service-token mode doesn't have.

## Pros and Cons of the Options

### 1. Enrich service token

* Good, because no refresh-token persistence is needed.
* Bad, because storage sees `sub=rucio` only; the user claim is an unverified audit hint, not an authorization input — the confused-deputy gap this ADR exists to close.

### 2. True user-subject token

* Good, because storage sees real per-user identity.
* Bad, because nothing distinguishes "Rucio relayed this" from "the user called storage directly" — a replayed token is indistinguishable from a legitimate direct call.
* Bad, because it needs the same refresh-token persistence as option 3, for strictly less information.

### 3. Token exchange with `act`

* Good, because it carries both subject and actor, audience-restricted, in one token.
* Bad, because it requires refresh-token persistence and a new store to hold it.

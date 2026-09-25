---
status: proposed
date: 2026-07-08
decision-makers: WP4, DEP architecture team
consulted: RSE operators, AAI/IAM operators
informed: DEP component owners
---

# ADR-002: Adopt a keyed multi-entry AAI credential file with a one-to-one RSE→issuer binding

## Context and Problem Statement

Rucio already supports multiple AAI/IdP configurations: `idpsecrets.json` is
keyed by IdP nickname, and users can select an issuer explicitly. Separately,
Rucio RSEs can carry arbitrary key/value attributes, and OIDC-related RSE
attributes already exist (`oidc_support`, `oidc_base_path`).

What is missing is a standard RSE → AAI/IdP binding: a first-class attribute
that tells Rucio "this RSE authenticates against issuer X," and a mechanism
that resolves that binding into credentials. Today the relationship between
an RSE and the issuer used for token acquisition is not represented as a
configuration concept at all.

This gap becomes a hard blocker once a component must deal with more than one
AAI at once — e.g. DLM needs source and destination tokens from different
AAIs, and different RSEs may each sit behind a different issuer.

Binding cardinality is explicitly one-to-one: each RSE binds to exactly one
issuer. DLM's need to hold tokens from multiple AAIs simultaneously is
satisfied because different RSEs can each bind to a different issuer, not
because a single RSE can bind to more than one. No RSE in the current
deployment is known to require more than one issuer.

Transfers are executed by background daemons (conveyor) rather than in an
interactive user session, so the tokens involved are assumed to be
service-level (client credentials), not delegated user identity — worth
confirming with the Rucio team rather than assuming (see Open Points). If
that assumption is later revisited toward user-delegated token exchange, a
static per-RSE credential is not sufficient on its own: exchanging a token
across two RSEs bound to different issuers additionally requires those
issuers to trust each other, which is out of scope here.

This is a credential/config lifecycle concern, distinct from and sitting
below the Authorization Service decision (ADR-001).

## Decision Drivers

* Support components acting as multi-AAI clients (e.g. DLM) without one-off
  config per component — via per-RSE binding, not per-RSE multi-binding.
* Support secret rotation and revocation without redeploying components.
* Let RSE/AAI bindings be discoverable rather than assumed or hardcoded.
* Keep the operational and development footprint small — extend the existing
  config-loading pattern rather than building new infrastructure.
* Keep the binding representation as simple as Rucio's existing flat
  RSE-attribute model allows, rather than pre-building support for a
  cardinality no current RSE needs.

## Considered Options

1. Static single-AAI JSON config per component (current state) — no
   RSE-level binding at all.
2. Multi-entry AAI credential file, keyed by binding name, with a new RSE
   attribute holding that key — constrained to one binding per RSE.
3. As (2), but allowing an RSE to hold multiple issuer bindings.
4. A dynamic registry service with its own lookup API, and/or an external
   secrets manager (e.g. Vault).

## Decision Outcome

Chosen option: **2. Multi-entry credential file, keyed by binding name, plus
a single-valued RSE attribute giving that key cross-component meaning**,
because it satisfies every decision driver — multi-AAI support, rotation
without redeploy, discoverability — without introducing a new service or
secrets-manager dependency, and because no current RSE needs more than one
issuer, so the one-to-one constraint costs nothing today.

The credential file structure is unchanged from today's single-issuer file,
just keyed by binding name instead of holding one entry. The RSE-to-IAM
binding is established solely through a new, single-valued RSE attribute
(e.g. `issuer_binding = egi-dev`), resolved by key lookup into the file.
Because the binding is one-to-one, a flat `rse_attribute` key→string pair is
sufficient — no JSON-valued attribute or protocol-definition change is
required.

### Positive Consequences

* No new service, lookup API, or secrets-manager dependency.
* Adding or rotating an AAI relationship is a single file-entry edit, not a
  redeploy or a find-and-replace across every RSE referencing it.
* Multi-AAI components (DLM) are supported without bespoke handling.
* The representation question (JSON-valued attribute vs. multiple keys vs.
  protocol change) does not need to be answered before implementation,
  because cardinality is fixed at one binding per RSE.

### Negative Consequences

* `client_secret` and SCIM credentials are at rest in the file, same as the
  current single-issuer config — this decision does not improve
  secret-at-rest posture.
* File-based config still needs a reload mechanism for changes to take
  effect without a full redeploy.
* An RSE that genuinely needs more than one issuer cannot be represented at
  all under this design — a hard constraint requiring a follow-up decision,
  not a soft limitation.
* `issuer_binding` is a new convention this ADR introduces, not an existing
  Rucio feature — every component reading RSE attributes must adopt it
  consistently or the binding silently fails to resolve.

## Open Points

* Confirm no current or near-term RSE requires more than one issuer binding;
  this decision depends on that holding true.
* Confirm the accepted risk level of `client_secret` at rest in this file is
  acceptable long-term, or whether it triggers the rejected secrets-manager
  option sooner than assumed.
* Verify with the Rucio team whether an experimental or DEP-specific Rucio
  branch already introduces an RSE→AAI binding attribute; if so, this ADR
  should align with it rather than defining a competing convention.
* Decide and document the behavior when an RSE has no `issuer_binding` set
  (hard error vs. fallback) before rollout.
* Confirm the "service-level token, not delegated user identity" assumption
  for conveyor-submitted transfers with the Rucio team.

## Confirmation

Compliance is confirmed by:

* A defined `issuer_binding` RSE attribute resolves, by key lookup, into the
  keyed credential file.
* Each RSE carries at most one `issuer_binding` value.
* A multi-AAI component (e.g. DLM) can be configured against N issuers by
  adding file entries and binding different RSEs to them, without code
  changes.
* No open question remains about multi-binding representation, because
  multi-binding is explicitly out of scope for this decision.

## Pros and Cons of the Options

### 1. Static single-AAI config (status quo)

* Good, because it requires no change.
* Bad, because it cannot support a multi-AAI component like DLM at all.
* Bad, because there is no RSE-level binding concept to build on.

### 2. Multi-entry file, one binding per RSE (chosen)

* Good, because it reuses the existing config-loading pattern with no new
  infrastructure.
* Good, because rotation is a single file-entry edit.
* Bad, because it cannot represent an RSE needing more than one issuer.

### 3. Multi-entry file, multiple bindings per RSE

* Good, because it would remove the one-issuer-per-RSE ceiling.
* Bad, because it solves a problem no current RSE has, at the cost of a
  JSON-valued attribute or a protocol-definition change.

### 4. Dynamic registry service and/or external secrets manager

* Good, because it offers live lookup and secrets-never-at-rest.
* Bad, because it adds a new deployable component and/or a hard external
  dependency without a demonstrated need at the current AAI/component count.

## Implementation notes (non-normative)

The material below describes how option 2 is wired, not why it was chosen.
It is retained here for now since no companion design doc yet exists for
this ADR; move it there if one is created.

Example credential file shape:

```json
{
  "egi-dev": {
    "issuer": "https://aai-dev.egi.eu/auth/realms/egi",
    "client_id": "...",
    "client_secret": "...",
    "redirect_uris": [...],
    "audience": "rucio",
    "scope": "openid profile eduperson_entitlement offline_access read:/ write:/",
    "SCIM": { "client_id": "...", "client_secret": "..." }
  },
  "atlas-iam": { "issuer": "...", "...": "..." }
}
```

Each component (Rucio, DLM) loads this file itself at startup, exactly as it
loads its current single-issuer file today — no new runtime dependency, no
service to stand up, no Vault integration. Reload behavior (SIGHUP, interval,
or restart) is an implementation detail. Many RSEs sharing the same issuer
point to the same entry, so rotating a `client_id`/`client_secret` is one
edit to one entry, not a find-and-replace across every RSE.

# Design 002 — Widening the OPA input before the contract is fixed

**Status:** proposed (2026-09-13). Precedes BACKLOG 4 (Authorization Service).
Does not depend on BACKLOG 5 (fine-grained ABAC) and does not attempt it.

## Problem

BACKLOG 4 step 1 is a thin passthrough that "validates the `/v1/authorize`
contract and operation-name mapping". Whatever shape that contract takes will
be hard to change once a generated client exists on the Rucio side, so it
should be designed against more than one requirement.

Today it would be designed against exactly one. `_build_input()` produces:

    {
      "issuer": issuer.external,
      "action": action,
      "token": {"entitlements": [...]},
      "kwargs": {...},
    }

`subject` would therefore be "an account name plus one entitlement list" and
`resource` would be "a bag of Rucio kwargs". Neither is a designed interface;
both are what the current implementation happens to emit.

Two things are already known to be missing:

- **Other claims.** `request.environ['token_claims']` carries the whole
  decoded payload — `acr`, `aud`, `iss`, `sub`, `wlcg.groups` — and
  `_extract_entitlements()` reads one key and discards the rest. Nothing
  downstream can use a claim that never leaves the policy module.
- **A non-role condition.** Every clause in rego/phase6 resolves to
  entitlement membership or kwargs-vs-issuer comparison. The
  `operation`/`subject`/`resource`/**`context`** shape in adr-001 has a
  `context` field with nothing in this repo to put in it.

`opa-ri-scale` (the DEP OPA bundle) already ships an input document with both:

    {
      "action": "read",
      "resource": {"id": "https://data.deps.eu/dataset/abc123"},
      "token": {
        "acr": "https://refeds.org/profile/mfa",
        "entitlements": ["urn:example:aai.example.org:group:project-x:role=member"]
      }
    }

and evaluates `acr` as a policy constraint. The entitlement URN format matches
this testbed's exactly, so the two are already aligned on subject identity and
differ only on what else travels alongside it.

## Scope

Three changes, none of which need the persona/use-case work that BACKLOG 5 is
blocked on:

### 1. Forward the whole claims dict

`_build_input()` puts the decoded payload under `token`, rather than
extracting one key from it:

    "token": _token_claims(),

with a small allowlist of keys rather than the raw payload, so the input
document stays readable in the debug log and no unexpected claim becomes
load-bearing by accident. Starting set: `entitlements`, `wlcg.groups`, `acr`,
`aud`, `iss`, `sub`.

Phase 4's `token.groups` and phase 5/6's `token.entitlements` stay where they
are — this adds keys, it doesn't move them, so no existing Rego clause or e2e
input document changes.

### 2. One constraint that isn't role membership

A privileged action additionally requires an authentication-context class
reference, when the bundle asks for one:

    _acr_satisfied if {
        not data.vo.policy.required_acr
    }

    _acr_satisfied if {
        input.token.acr == data.vo.policy.required_acr
    }

Default is absent, so the testbed behaves as it does now; setting
`data.vo.policy.required_acr` at runtime turns it on. This is deliberately the
same claim and the same REFEDS value opa-ri-scale uses, so a future shared
policy layer does not have to reconcile two conventions.

Which actions it gates is a policy question — the narrow version is
`_is_privileged`, so an admin entitlement alone stops being sufficient.

### 3. A privilege level that is not "admin"

`_is_privileged` compares `_entitlement_privilege(e) == "admin"`. The bundle's
`rucio-users → "user"` mapping is documentation: a non-admin entitlement and
no entitlement at all reach identical clauses.

Introduce a level lookup that at least one rule consults, so the bundle's
second tier is real. The minimal version: an entitlement mapped to `"user"`
satisfies a clause that an account with no entitlement does not — e.g.
`add_replicas` without needing
`allow_replica_writes_to_allowlisted_rses` globally on.

This is not ABAC and does not pre-empt BACKLOG 5. It only makes the existing
two-level bundle mean something, which is what a `subject` field in the
contract has to be able to express.

## Non-goals

- Per-RSE / per-scope ABAC, time windows, maintenance windows. BACKLOG 5,
  still gated on a use-case and persona overview — policies modelled against
  real access patterns rather than a guessed ABAC shape.
- Any change to the `action` strings or `kwargs` keys. Both are fixed by
  Rucio's gateway; see docs/policy-package-mechanism.md.
- Bundle distribution. `ingest_policies.py` PUTs policy and data at startup;
  opa-ri-scale builds an OCI bundle and polls it. That is the better model for
  anything long-lived, but it is orthogonal to the input shape and belongs in
  its own decision.

## What this unblocks

When BACKLOG 4 step 1 designs `/v1/authorize`, it will have three distinct
requirements to design against rather than one:

| Contract field | Grounded in |
|---|---|
| `subject` | entitlements *and* a privilege level, not a single admin flag |
| `context` | `acr`, a real constraint with a real rule consuming it |
| `resource` | unchanged — still Rucio kwargs, and still the open question |

`resource` stays the hard part. opa-ri-scale models it as a URI
(`resource.id`); this package has `kwargs.rse_expression`, `kwargs.scope`,
`kwargs.rse_id`. Reconciling those is the substance of the Authorization
Service contract and is out of scope here — but it is easier to argue about
with the other two fields settled.

## Related, not blocking

OPA's own API is unauthenticated in every compose file: it listens on 8181
inside the docker network with no `--authentication`/`--authorization`, so
anything that can reach it can `PUT /v1/data/vo/entitlement_policy` and grant
itself admin. Acceptable in a testbed, not acceptable anywhere else, and worth
a note in the phase READMEs before someone copies a compose file.
opa-ri-scale's `system.authz` package (token introspection in Rego, write
methods gated on group membership) is the reference for doing this properly.

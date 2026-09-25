# Design-007 — Folding phase 6 into phase 7 via a dispatch flag

Status: draft, unreviewed. Prerequisite for the dep-dlm-testbed
flag question (BACKLOG item 8) and informs whether phase 6 stays a
separate numbered phase going forward.

## Premise

Phase 6 and phase 7 already share one policy: `authz.rego`'s decision
logic (scope/rule ownership, RSE naming, entitlement-derived
privilege) is identical between them except for the changes phase 7's
own header comments mark "Changed from phase 6" — same rules,
restructured to match the Authorization Service contract. The two
phases differ only in *how* `has_permission()` reaches that logic:
phase 6 queries OPA directly from Rucio's process; phase 7 calls the
Authorization Service over HTTP via a generated client.

If dep-dlm-testbed wants both paths available, the natural
implementation is a dispatch flag inside one `permission.py`, not two
maintained phase packages.

## Proposed shape

```
AUTHZ_MODE=direct   # has_permission() queries OPA directly (phase-6 path)
AUTHZ_MODE=service  # has_permission() calls authz-service via
                     # rucio_authz_client (phase-7 path)
```

Both modes read the **same** `authz.rego` and the **same**
`entitlement_policy`/`vo.policy` data bundle. The flag changes only
the transport `has_permission()` uses to reach a decision — never the
decision content itself. This is the same principle already used to
avoid `docker/authz.rego` drifting from the root repo's copy (kept in
sync by hand, single source of truth in intent even if duplicated in
file), just enforced structurally instead of by convention.

## What folds, what doesn't

**Folds:**
- `phases/phase6-opa` and `phases/phase7-opa` → one package
  (`rucio_opa_policy` or similar), with `AUTHZ_MODE` selecting
  `opa_client.py` (direct) vs. `rucio_authz_client`-backed dispatch
  (service) inside one `permission.py`.
- `policies/rego/phase6/authz.rego` and `policies/rego/phase7/authz.rego`
  → one file, since they're already meant to encode the same decisions.
- `tests/test_phase6_rucio.py` / `test_phase7_rucio.py` → one suite,
  parametrized over `AUTHZ_MODE` rather than duplicated per phase.

**Does not fold:**
- `deploy/compose/docker-compose.phase6.yml` vs. `phase7.yml` — these
  stay distinct, since `AUTHZ_MODE=service` genuinely needs the
  authz-service, OPA, and Keycloak client wiring that `direct` mode
  doesn't. The compose file is what differs by topology, not the
  policy package.
- ADR-004/005/006 — these describe the service's existence and
  placement, which remains true whenever `AUTHZ_MODE=service` is
  selected; folding the phases doesn't retire the service or its
  design docs.

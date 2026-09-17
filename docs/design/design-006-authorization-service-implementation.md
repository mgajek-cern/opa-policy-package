# Design 006: Authorization Service implementation

**Status:** proposed (2026-09-17).

**Implements:** [design-005](design-005-authorization-service-api.md), the
contract. [ADR-004](../adrs/adr-004-authorization-service-implementation.md)
records the reasons behind the choices and the invariants. This document covers
how they are carried out.

**Starting point:** phase 7, the policy package calling OPA directly with the
`vo.authz.v6` Rego. Phase 7 is migrated in place.

## Summary

The service is a stateless Python application: a decision core with a PDP port,
an HTTP adapter in front and a PDP adapter behind. OPA is the only PDP adapter
today. Nothing is persisted; telemetry, including audit records, leaves through
OpenTelemetry.

The phase 7 policy package hands its actions to the service one operation group
at a time. When all groups are handed over, the package's direct OPA code is
deleted.

## Invariants

ADR-004 explains why these hold. "Conformance checks" lists how each is
enforced.

1. **Fail closed.** Only an explicit *permit* from the PDP yields
   `decision: true`. Every other outcome is a deny or an error, and the PEP
   treats every error as a deny.
2. **Alignment.** Contract operations, routes, core catalogue, PEP transport
   functions and the PDP policy's known actions stay identical.
3. **Dependency direction.** The core never imports the web framework,
   pydantic, a PDP client, the OTel SDK or an adapter.
4. **Audit data boundary.** Personal and confidential fields appear only in
   audit records. Raw tokens appear nowhere.
5. **No persistence.** No state beyond in-process caches.

## Scope

In scope: the v1 contract
([openapi.yaml](../../services/authorization-service/api/openapi.yaml)), the
OPA adapter, PEP authentication, telemetry, and migrating the phase 7 package.

Out of scope: `transfer.authorize`, AuthZEN endpoints, caching, multi-VO, and
PDPs other than OPA. The port allows other PDPs; this plan builds none.

## Architecture

### Layout

```
services/authorization-service/
  Makefile, pyproject.toml, Dockerfile
  api/openapi.yaml                  # source of truth
  src/authz_service/
    main.py                         # composition root; the only place a PDP adapter is chosen
    settings.py
    core/
      model.py                      # Subject, Resource, Evaluation, Outcome, Decision
      catalogue.py                  # operations: typed vs privileged-only
      decide.py                     # evaluate, apply outcome rules, emit audit record
      ports.py                      # PolicyDecisionPoint
    api/
      generated/models.py           # generated; never edited
      routes/                       # one module per contract tag
      auth.py, errors.py, health.py
    adapters/pdp/opa/
      client.py                     # HTTP client, explicit timeout, no retries
      translate.py                  # Evaluation → OPA input; OPA result → Outcome
    telemetry/setup.py
  tests/unit/                       # pure logic only
  tests/integration/
```

### The PDP port

The core speaks in PDP-neutral terms. The port takes an `Evaluation` and
returns an `Outcome`:

| Outcome | Meaning | Service response |
|---|---|---|
| `PERMIT` | The policy allows the action | 200, `decision: true` |
| `DENY` | The policy refuses the action | 200, `decision: false` |
| `NOT_APPLICABLE` | The PDP has no applicable policy, e.g. none loaded | 500: a deployment fault, not a decision |
| `INDETERMINATE` | The PDP could not decide: unreachable, timeout, malformed answer | 503 |

These are the outcome categories XACML uses, so any PDP maps onto them. Each
adapter owns the mapping, and nothing PDP-specific crosses the port. The port
also exposes the PDP's policy id and revision for audit records, and its known
actions for the alignment check.

**OPA adapter.** Result `true` → `PERMIT`; `false` → `DENY`; no `result` key →
`NOT_APPLICABLE`; timeout, connection error, 5xx or invalid JSON →
`INDETERMINATE`. It builds the same input document the phase 7 Rego and tests
already use, so decisions carry over unchanged. It reads the policy revision
from `data.vo.meta`, which `ingest_policies.py` writes, and known actions from
`_all_known_actions`.

### Operations

The core's `Evaluation` carries a PDP-neutral action name, the subject, the
resources with their owners, and the context. Multi-resource requests are one
evaluation, permitted only if every resource is.

| Endpoint | Action | Resources and attributes |
|---|---|---|
| `rules/{create,update,delete}` | `add_rule`, `update_rule`, `del_rule` | rule owner, target and DID scopes with owners; `locked`, RSE expressions; reassignment |
| `dids/{create,attach,detach}` | `add_dids`, `attach_dids_to_dids`, `detach_dids` | DIDs or parents, with scope owners |
| `rses/*`, `protocols/*` | `add_rse`, `update_rse`, `del_rse`, `add_rse_attribute`, `del_rse_attribute`, `*_protocol` | RSE name; new name; attribute key; scheme |
| `replicas/{register,delete}` | `add_replicas`, `delete_replicas` | RSE; files with scope owners |
| `privileged-operations` | the named operation | none |

### What moves out of the policy package

| Concern | Phase 7 package today | After migration |
|---|---|---|
| Token claims from the request | `_token_claims()` | Stays in the package |
| Rule and scope facts from Rucio's database | `_rule_facts()`, `_owned_scopes()` | Stays; returns owners |
| Kwargs allowlist, externalising | `_serialisable_kwargs()`, `_externalise()` | One request builder per operation |
| OPA input, OPA call, fail closed | `_build_input()`, `opa_client.py` | Service (core and OPA adapter); deleted from the package |
| Decision logging | debug `log.warning` | Audit record in the service; package logs `decision_id` |

### Migration

Until the last group is handed over, `has_permission()` checks one set:

- actions in the set → the service transport;
- all other actions → the existing direct OPA path.

Handing over a group means adding its actions to that set, in one change
together with the service routes for the group. There is no shadow mode and no
runtime switch. Two things show a handover is safe: the group's contract
vectors pass through the service, and the phase 7 e2e suites pass. To roll back,
revert the change.

Order:
1. `rules/delete`
2. the remaining rules operations
3. DIDs
4. RSEs and protocols
5. replicas
6. `privileged-operations`, last, because the root bootstrap depends on it

This is a minimal form of the strangler fig pattern: operation groups move to the service one at a time while the direct OPA path serves the rest. It deliberately omits the pattern's usual traffic-shadowing and runtime routing, which would cost more than they protect in a testbed whose decisions are already pinned by contract vectors.

### Code generation

The service runs on Python 3.12 and uses the current `datamodel-code-generator`.
The package runs inside Rucio's server image, on Python 3.9. That rules out
current generators, which was checked:

- `openapi-python-client` 0.29.1 output needs Python 3.11.
- `datamodel-code-generator` 0.82.0 can't target 3.9.

`datamodel-code-generator==0.26.5` with `--target-python-version 3.9` does work
against the spec. So the package uses those generated models plus a
hand-written transport of one function per `operationId`.

- **Pinning.** The generator version is pinned exactly and the generated output
  committed.
- **CI check.** CI regenerates and fails on any diff.
- **Upgrade trigger.** The pin changes only when Rucio's image moves past
  Python 3.9.

Before step 4, check the image with
`docker run --rm rucio/rucio-server:release-41.2.1 pip show pydantic requests`.
If pydantic v2 conflicts, generate dataclasses instead. If `requests` is
present, use it for the transport.

### Configuration

**Service:**

| Variable | Default |
|---|---|
| `AUTHZ_PDP` | `opa` |
| `AUTHZ_PDP_TIMEOUT_SECONDS` | `1.0` |
| `AUTHZ_OIDC_ISSUER`, `AUTHZ_OIDC_AUDIENCE` | required |
| `AUTHZ_REQUIRED_SCOPE` | `pep:rucio` |
| `OTEL_*` | standard OTel SDK variables |

Adapter-specific settings are namespaced per adapter, e.g. `AUTHZ_OPA_URL`
(required) and `AUTHZ_OPA_POLICY_PATH` (default `vo/authz/v6/allow`).
Authentication cannot be disabled.

**Rucio services:**

| Variable | Purpose |
|---|---|
| `AUTHZ_SERVICE_URL` | Service base URL |
| `AUTHZ_SERVICE_TIMEOUT_SECONDS` | Must exceed `AUTHZ_PDP_TIMEOUT_SECONDS` |

The package also holds `pep:rucio` client credentials and caches their token.

## Telemetry

Everything leaves through OTLP; the collector decides retention.

- **Traces.** Framework and HTTP-client instrumentation, plus one
  `authz.decide` span per decision. The span carries operation, decision,
  outcome, PEP client, policy id and `decision_id`, and no personal data.
- **Metrics.**
  - `authz.decisions`: counter, by operation, decision and PEP client.
  - `authz.decision.duration`: histogram, by operation. The p99 budget is read
    from this.
  - `authz.pdp.outcomes`: counter, by outcome.
- **Audit records.** One OTel log record per decision, on the `authz.audit`
  logger, separate from application logs.

### Audit record

| Field | Classification |
|---|---|
| `decision_id`, `timestamp`, `trace_id`, `pep.client_id` | operational |
| `operation`, `decision`, `outcome`, `policy.id`, `policy.revision`, `duration_ms`, `reason_admin` | operational |
| `token.jti` | operational |
| `subject.type`, `subject.id`, `token.iss`, `token.sub`, `claims.entitlements`, `claims.acr` | personal |
| `resources` (scope, name, owner, RSE) | confidential |

`reason_admin` must not echo personal or confidential values.

Never recorded: raw tokens or signatures, secrets, `Authorization` headers, full
request bodies, or claims the policy doesn't read.

The service defines this schema. The collector backend's owner defines
retention and access, and must be named before step 4.

## Testing

**Integration tests are authoritative.** They run with `pytest`, and fixtures
own every container through `testcontainers`:

- **`pdp`:** an OPA container with the phase 7 Rego and data from
  `ingest_policies.py`.
- **`issuer`:** a mock OAuth2 issuer.
- **`service`:** the app, run in-process.
- **`client`:** the package's transport.
- **`keycloak`:** auth interop suite only.
- **`toxiproxy`:** failure-mode suite only.

**Unit tests** are allowed only for pure logic: the catalogue, translation in
the PDP adapter, and outcome classification.

| Suite | Checks |
|---|---|
| `test_contract_*` | Every phase 7 vector as a contract request, with the same expected decision. The suite is PDP-independent: another adapter must pass it unchanged. |
| `test_failure_modes` | PDP stopped or slow → 503; no policy loaded → 500; malformed answer → 503; never `decision: true` |
| `test_auth` | No token → 401; missing `pep:rucio` → 403; wrong issuer or audience → 401 |
| `test_telemetry` | The span, metrics and audit record exist; no personal or confidential field outside the audit record; no raw token |
| `test_alignment` | Spec, routes, catalogue, transport and the PDP's known actions agree |

## Conformance checks

ADR-004 is confirmed when these pass in CI:

| Invariant | Check |
|---|---|
| 1. Fail closed | `test_failure_modes` |
| 2. Alignment | `test_alignment` |
| 3. Dependency direction | Import-linter: `authz_service.core` must not import `fastapi`, `pydantic`, `httpx`, `opentelemetry.sdk`, `authz_service.api`, `authz_service.adapters` |
| 4. Audit data boundary | `test_telemetry` |
| Unit tests restricted | Import-linter: `tests.unit` imports only `authz_service.core` and `authz_service.adapters.pdp.opa.translate`; no HTTP-mocking library installed |
| Generated models current | `check-generated` |

CI runs:

```
make -C services/authorization-service check-generated lint typecheck test
```

Makefile targets: `spec-validate`, `generate`, `check-generated`, `lint`
(ruff and import-linter), `typecheck`, `test`, `run`, `image`.

## Sequencing

Steps 0 and 1 can run in parallel. Each step ends merged and green.

| # | Step | Done when |
|---|---|---|
| 0 | Phase 7 baseline: replication fixes, replica gateway patch (`files` forwarded to `has_permission`), design-005 amendments, p99 budget set | `make e2e PHASE=7` passes in CI, including a user upload |
| 1 | Service skeleton: settings, health, OTel setup, image, `pdp` fixture | `make test` passes in CI |
| 2 | `rules/delete` in the service: core, port, OPA adapter, errors, PEP authentication, audit record, metrics, policy revision | Its contract vectors, `test_failure_modes`, `test_auth`, Keycloak interop and `test_telemetry` pass |
| 3 | Hand over `rules/delete`: package transport and token, service and collector in phase 7 compose | Phase 7 e2e passes; audit records visible in the collector |
| 4 | Hand over the remaining groups, in order | All contract vectors, `test_alignment` and phase 7 e2e pass; p99 within budget |
| 5 | Delete the package's direct OPA path and the OPA settings in the Rucio services; rate and payload limits; image scan | Phase 7 e2e passes; limits enforced |

Authentication and the telemetry checks ship with the first operation, so the
package never calls an unauthenticated service, and the first audit record
arrives already checked for personal data. The p99 budget is checked while the
direct OPA path still exists to fall back to. `privileged-operations` goes last
because the root bootstrap depends on it.

## Risks

- **Python 3.9 in Rucio** keeps the package on a pinned generator. Contained by
  `check-generated` and the single upgrade trigger.
- **A synchronous hop on every Rucio write.** Contained by the step 8 budget,
  connection reuse, and co-locating the PDP.
- **Trust in asserted claims.** The PEP client registry needs an owner before
  step 3.
- **Mixed routing during handover.** The handed-over set is versioned code;
  each handover is one revertable change.

## Changes needed elsewhere

- **design-005 (step 0):**
  - multi-resource requests are one evaluation, permitted only if every resource
    is;
  - `NOT_APPLICABLE` → 500 and `INDETERMINATE` → 503, and a PEP never receives a
    permit from a PDP failure;
  - phase 7 is migrated in place, one operation group at a time.
- **`scripts/ingest_policies.py`:** write `data.vo.meta` with policy id and
  revision.
- **CI:** the service job above.

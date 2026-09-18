# DEP Authorization Service

Decisions for Policy Enforcement Points. Implemented per
[design-006](../../docs/design/design-006-authorization-service-implementation.md);
the reasons and invariants are in
[ADR-004](../../docs/adrs/adr-004-authorization-service-implementation.md).

This is the skeleton: settings, health, telemetry, the PDP port and the OPA
adapter's connectivity. Decision endpoints arrive one operation group at a
time, starting with `rules/delete`.

## Layout

| Path | Holds |
|---|---|
| `api/openapi.yaml` | The contract. Source of truth for routes and models. |
| `src/authz_service/core/` | Decision model and the `PolicyDecisionPoint` port. No framework, no PDP, no OTel SDK. |
| `src/authz_service/api/` | HTTP adapter: health today, routes per contract tag later. |
| `src/authz_service/adapters/pdp/opa/` | Everything OPA-specific. |
| `src/authz_service/telemetry/` | The only place the OTel SDK is configured. |
| `src/authz_service/main.py` | Composition root; the only place a PDP adapter is chosen. |
| `tests/unit/` | Pure logic only. |
| `tests/integration/` | Authoritative. Fixtures own the containers. |

## Getting started

```
make venv      # create .venv and install the package with dev extras
make lint      # ruff and the import contracts
make typecheck # mypy
make test      # unit tests, then integration tests (needs Docker)
make run       # local server on :8000
```

`make test` starts an OPA container through testcontainers, loads
`policies/rego/phase7/authz.rego` and the phase 7 data from
`scripts/ingest_policies.py`, and runs the service in-process against it.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `AUTHZ_PDP` | `opa` | Which adapter `main.build_pdp` selects |
| `AUTHZ_PDP_TIMEOUT_SECONDS` | `1.0` | Must stay below the PEP's timeout |
| `AUTHZ_OPA_URL` | required | Adapter-specific, namespaced per adapter |
| `AUTHZ_OPA_POLICY_PATH` | `vo/authz/v6/allow` | |
| `AUTHZ_OIDC_ISSUER`, `AUTHZ_OIDC_AUDIENCE` | unset | Become required when PEP authentication lands |
| `AUTHZ_REQUIRED_SCOPE` | `pep:rucio` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Without it the OTel API stays a no-op |

## Generated models

`make generate` writes two model sets from the contract: one for the service
and one for the Rucio policy package, the latter with a pinned generator that
still targets Python 3.9. Neither is committed yet; they arrive with the first
operation, after which `make check-generated` keeps them in step with the spec.

# DEP Authorization Service

Decisions for Policy Enforcement Points. Implemented per
[design-006](https://github.com/mgajek-cern/opa-policy-package/tree/main/docs/design/design-006-authorization-service-implementation.md);
the reasons and invariants are in
[ADR-004](https://github.com/mgajek-cern/opa-policy-package/tree/main/docs/adrs/adr-004-authorization-service-implementation.md).

This is the skeleton: settings, health, telemetry, the PDP port and the OPA
adapter's connectivity. Decision endpoints arrive one operation group at a
time, starting with `rules/delete`.

## Layout

See [docs/adding-an-endpoint.md](docs/adding-an-endpoint.md) for the step-by-step for adding a new decision endpoint, contract through tests.

| Path | Holds |
|---|---|
| `api/openapi.yaml` | The contract. Source of truth for routes and models. |
| `src/authz_service/core/` | Decision model and the `PolicyDecisionPoint` port. No framework, no PDP, no OTel SDK. |
| `src/authz_service/api/` | HTTP adapter: health and routes per contract. |
| `src/authz_service/api/generated/` | Server stubs and models generated from the contract (`make generate-server-stubs`). Reference only, permanently — `models.py` is what `api/routes/` actually imports, but `main.py`/`routers/` here will never match the hand-written routers signature-for-signature: `fastapi-code-generator` has no way to know about `Depends(validated_claims)` or any other project-specific dependency, so every generated route takes only its request body where the real one also takes a validated token. That's expected drift, not staleness to fix. |
| `src/authz_service/adapters/pdp/opa/` | Everything OPA-specific. |
| `src/authz_service/telemetry/` | The only place the OTel SDK is configured. |
| `src/authz_service/main.py` | Composition root; the only place a PDP adapter is chosen. |
| `clients/python/` | Standalone typed client for PEPs (e.g. Rucio), generated from the contract (`make generate-client`). |
| `tests/unit/` | Pure logic only. |
| `tests/integration/` | Authoritative. Fixtures own the containers. |
| `docker/authz.rego`, `docker/realm.json` | The service's own copies for its dev/test OPA and Keycloak — duplicated from the root repo's `policies/rego/phase7/` and `configs/keycloak/phase7/`, not shared, so this service's tests and `make up` need no root-repo checkout. |


## Getting started

```
make venv      # create .venv and install the package with dev extras
make lint      # ruff and the import contracts
make typecheck # mypy
make test      # unit tests, then integration tests (needs Docker)
make up        # start OPA and Keycloak for manual `make run`;
               #`make test` provisions its own via testcontainers
export AUTHZ_OIDC_ISSUER=http://keycloak:8080/realms/rucio
export AUTHZ_OIDC_AUDIENCE=authz-service
export AUTHZ_OPA_URL=http://localhost:8181
make run       # local server on :8000
```

`make test` starts an OPA container through testcontainers, loads
`docker/authz.rego` and the phase 7 data from
`scripts/ingest_policies.py`, and runs the service in-process against it.

`opa-init` is a one-shot container that waits for OPA's health endpoint,
loads the same policy bundle, then exits — `make up` returns
before it finishes, so if `make run` starts against an unindexed OPA,
`pdp.evaluate()` fails closed (`NOT_APPLICABLE`) rather than erroring;
check `docker compose logs opa-init` if that happens.

To regenerate server stubs or the typed client from `api/openapi.yaml`:

```
make tools                  # one-off: installs fastapi-code-generator and
                            # openapi-python-client into .venv-codegen, kept
                            # separate from .venv (see "Generated code" below)
make generate-server-stubs  # -> src/authz_service/api/generated/
make generate-client        # -> clients/python/
```

## Make Targets

```bash
  help                     List targets
  venv                     Create the dev environment
  tools                    Create the isolated env for the route/client generators
  spec-validate            Validate the OpenAPI contract
  generate-server-stubs    Scaffold per-tag server stubs fromthe contract (reference only, not wired in — see README)
  generate-client          Generate a standalone typed Pythonclient from the contract
  generate-client-phase7   Generate phase7's client via openapi-generator python-legacy (3.9-safe)
  lint                     ruff and the import contracts
  typecheck                mypy
  test                     Unit tests, then integration tests(needs Docker)
  demo-client              poke a running instance via the generated client (needs `make run` up)
  test-token-exchange      exercise the realm.json exchange flow and check required claims
  run                      Run locally
  image                    Build the container image
  up                       Start the service's own dev/test compose stack (OPA + Keycloak)
  down                     Stop the dev/test compose stack, keeping volumes
  clean                    Stop the dev/test compose stack and wipe volumes
```

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

## Generated code

Everything under `src/authz_service/api/generated/` and `clients/python/` is
produced from `api/openapi.yaml` and committed as-is — treat it as a build
artifact, not hand-edited source (it's excluded from `ruff`/formatting for
the same reason). `make generate-server-stubs` and `make generate-client` need
`fastapi-code-generator` and `openapi-python-client`, which live in their own
venv (`.venv-codegen`, via `make tools`) rather than `[dev]`.

## Debugging in VS Code

`.vscode/launch.json` has a "Python: FastAPI (authz-service)" config that
runs `uvicorn authz_service.main:create_app --factory --reload` (the app is
built by a factory, not a module-level `app`). Start `make up`
first, then optionally set a breakpoint in [src/authz_service/main.py](src/authz_service/main.py)
and launch it from the Run and Debug dropdown.

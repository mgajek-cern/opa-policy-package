# Adding a decision endpoint

Worked example: rules/delete, followed for every operation group since.

1. Contract: add the operation to [openapi.yaml](../api/openapi.yaml) (request/response schemas,
   security scheme). `make spec-validate`.
2. Rego: add a `_perm_<action>` rule in [authz.rego](../../../policies/rego/phase7/authz.rego),
   plus a dispatch line in `_action_allowed`. Alignment is checked by
   [test_phase7_opa.py's](../../../tests/test_phase7_opa.py) `TestContractAlignment`
   class — at the repo root, not under this service's own `tests/`, since it
   checks `openapi.yaml` against `authz.rego` directly and shares fixtures
   with the phase-6 policy suite. Also add the new `operationId` to
   `ACTIONS_BY_OPERATION_ID` there, or `test_every_contract_operation_is_mapped`
   will fail on the next run. (**TODO:** Move authz.rego and realm.json into `authz_service` dirs and recover removed opa test in into `authz_service` dirs)
3. Route: hand-write api/routes/<tag>.py — NOT [api/generated/](../src/authz_service/api/generated/), which is
   reference only (see [README's](../README.md) Generated code section) and can't express
   `Depends(validated_claims)`. Call `subject_from(body.subject, token)` and
   `decide(pdp, evaluation)`.
4. Client: `make generate-client` picks up the new operation automatically.
5. Tests: add cases to [tests/integration/test_client_e2e.py](../tests/integration/test_client_e2e.py) via the
   generated client; [tests/unit/test_translate.py](../tests/unit/test_translate.py) for the OPA-input
   shape if [translate.py](../src/authz_service/adapters/pdp/opa/translate.py) needed a new kwargs builder.
6. If the operation needs new token claims beyond entitlements/acr —
   check whether realm.json's target client (authz-service) actually
   exposes them; legacy Keycloak token exchange computes scope/claims
   from the TARGET client's own scope config, not the requester's
   (see realm.json's authz-service client comment).

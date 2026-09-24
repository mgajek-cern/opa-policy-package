# Adding a decision endpoint

Worked example: rules/delete, followed for every operation group since.

1. Contract: add the operation to [openapi.yaml](../api/openapi.yaml) (request/response schemas,
   security scheme). `make spec-validate`.
2. Rego: add a `_perm_<action>` rule in [authz.rego](../docker/authz.rego),
   plus a dispatch line in `_action_allowed` and the action itself to
   `_all_known_actions`. Mirror the same change in the root repo's
   `policies/rego/phase7/authz.rego` — this service's copy is duplicated,
   not shared, so the two need to be kept in step by hand. There's no
   automated contract/Rego alignment check today (the one that used to run
   this, `tests/test_phase7_opa.py`, was retired during the authz-service
   rewrite); verify manually that the operationId in openapi.yaml and the
   action name in authz.rego agree, and that
   `PolicyDecisionPoint.known_actions()` (backed by `_all_known_actions`)
   returns it, since `privileged.py`'s 400-collision check depends on that
   list being accurate. Quickest way to check directly, once `make up`
   has OPA running with `docker/authz.rego` loaded:

   ```bash
   curl -s http://localhost:8181/v1/data/vo/authz/v6/_all_known_actions | jq
   curl -s -X POST http://localhost:8181/v1/data/vo/authz/v6/allow \
     -H 'Content-Type: application/json' \
     -d '{"input": {"issuer": "root", "action": "<new_action>", "token": {}, "kwargs": {}}}' | jq
   ```
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
   (see docker/realm.json's authz-service client comment).

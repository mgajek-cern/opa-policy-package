"""Every contract router is registered on the app (design-006,
"Alignment", partial coverage).

Full per-outcome behavior of authorize_rule_delete is covered by
tests/integration/test_evaluate.py against a real OPA; this only checks
that every router is wired into main.py's create_app(), that parked
operations answer honestly (501, application/problem+json) rather than
404ing, and that the one real route doesn't 404 either. A complete
test_alignment (spec operationIds vs. registered routes vs. the OPA
adapter's dispatch table) is still open, per the design doc's own
Testing section.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from authz_service.main import create_app

PROBLEM_MEDIA_TYPE = "application/problem+json"

_SUBJECT = {"type": "oidc_subject", "id": "randomaccount"}
_CONTEXT = {"vo": "def"}
_SCOPE = {"name": "test", "owner": "randomaccount"}
_DID = {"scope": _SCOPE, "name": "file1"}
_RSE = {"name": "CERN_DATADISK"}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    # Unreachable on purpose: these tests check routing and status codes,
    # not PDP behavior (that's test_evaluate.py, against a real OPA).
    monkeypatch.setenv("AUTHZ_PDP", "opa")
    monkeypatch.setenv("AUTHZ_OPA_URL", "http://127.0.0.1:1")
    with TestClient(create_app()) as test_client:
        yield test_client


# One minimal, schema-valid body per parked operation, so each request
# actually reaches the handler (422 on an invalid body would otherwise
# make a "returns 501" assertion pass for the wrong reason).
PARKED_OPERATIONS: dict[str, dict[str, object]] = {
    "/v1/decisions/rules/create": {
        "subject": _SUBJECT,
        "rule": {"owner": "randomaccount", "locked": False, "dids": [_DID]},
        "context": _CONTEXT,
    },
    "/v1/decisions/rules/update": {
        "subject": _SUBJECT,
        "rule": {"id": "rule-1", "owner": "randomaccount", "target": _DID},
        "changes": {},
        "context": _CONTEXT,
    },
    "/v1/decisions/dids/create": {
        "subject": _SUBJECT,
        "dids": [_DID],
        "context": _CONTEXT,
    },
    "/v1/decisions/dids/attach": {
        "subject": _SUBJECT,
        "attachments": [{"parent": _DID, "children": []}],
        "context": _CONTEXT,
    },
    "/v1/decisions/dids/detach": {
        "subject": _SUBJECT,
        "parent": _DID,
        "children": [],
        "context": _CONTEXT,
    },
    "/v1/decisions/rses/create": {"subject": _SUBJECT, "rse": _RSE, "context": _CONTEXT},
    "/v1/decisions/rses/update": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "changes": {},
        "context": _CONTEXT,
    },
    "/v1/decisions/rses/delete": {"subject": _SUBJECT, "rse": _RSE, "context": _CONTEXT},
    "/v1/decisions/rses/attributes/set": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "attribute": {"key": "fts"},
        "context": _CONTEXT,
    },
    "/v1/decisions/rses/attributes/delete": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "attribute": {"key": "fts"},
        "context": _CONTEXT,
    },
    "/v1/decisions/protocols/create": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "protocol": {},
        "context": _CONTEXT,
    },
    "/v1/decisions/protocols/update": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "protocol": {},
        "context": _CONTEXT,
    },
    "/v1/decisions/protocols/delete": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "protocol": {},
        "context": _CONTEXT,
    },
    "/v1/decisions/replicas/register": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "files": [_DID],
        "context": _CONTEXT,
    },
    "/v1/decisions/replicas/delete": {
        "subject": _SUBJECT,
        "rse": _RSE,
        "files": [_DID],
        "context": _CONTEXT,
    },
    "/v1/decisions/privileged-operations": {
        "subject": _SUBJECT,
        "operation": "add_account",
        "context": _CONTEXT,
    },
}


@pytest.mark.parametrize("path", PARKED_OPERATIONS)
def test_parked_operation_answers_501_problem(client: TestClient, path: str) -> None:
    response = client.post(path, json=PARKED_OPERATIONS[path])
    assert response.status_code == 501
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE


def test_rules_delete_route_is_registered_and_reaches_the_pdp(client: TestClient) -> None:
    """Doesn't assert the outcome (that's test_evaluate.py) — only that
    the route exists and a valid request reaches pdp.evaluate(), which
    an unreachable PDP turns into 503, not 404."""
    body = {
        "subject": _SUBJECT,
        "rule": {"id": "rule-1", "owner": "randomaccount", "target": _DID},
        "context": _CONTEXT,
    }
    response = client.post("/v1/decisions/rules/delete", json=body)
    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE


def test_healthz_route_is_registered(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code in (200, 503)

"""api.errors.install_handlers: ProblemError and the unhandled-exception
catch-all both produce a correctly-shaped RFC 9457 response, independent
of any specific route (unit, not integration — no PDP or OTel involved).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authz_service.api.errors import PROBLEM_MEDIA_TYPE, ProblemError, install_handlers


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = FastAPI()
    install_handlers(app)

    @app.get("/problem")
    async def raise_problem() -> None:
        raise ProblemError(403, "Forbidden", detail="no pep:rucio scope")

    @app.get("/boom")
    async def raise_unexpected() -> None:
        raise RuntimeError("something the route didn't anticipate")

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_problem_error_produces_its_own_status_and_detail(client: TestClient) -> None:
    response = client.get("/problem")
    assert response.status_code == 403
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE
    body = response.json()
    assert body["title"] == "Forbidden"
    assert body["status"] == 403
    assert body["detail"] == "no pep:rucio scope"


def test_unhandled_exception_becomes_500_problem_not_a_raw_traceback(client: TestClient) -> None:
    """The fail-closed guarantee (ADR-004, invariant 1) has to hold even
    for bugs the route author didn't anticipate — a leaked traceback or
    an unhandled 500 with no problem+json body is not a safe failure
    mode for a PEP that's supposed to treat every error as a deny."""
    response = client.get("/boom")
    assert response.status_code == 500
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE
    body = response.json()
    assert body["title"] == "Internal error"
    assert "detail" not in body  # no internals leaked to the client

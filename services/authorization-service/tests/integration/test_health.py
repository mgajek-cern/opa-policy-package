"""Health endpoint against a real PDP."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from authz_service.main import create_app
from authz_service.settings import Settings


def test_healthz_ok_when_pdp_reachable(client: httpx.Client) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_healthz_503_when_pdp_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second app instance pointed at a dead port, so the session's PDP
    container stays up for the other tests."""
    monkeypatch.setenv("AUTHZ_OPA_URL", "http://127.0.0.1:1")
    app = create_app(
        Settings(
            pdp="opa",
            pdp_timeout_seconds=0.5,
            oidc_issuer="http://unused.invalid",
            oidc_audience="authz-service",
        )
    )

    # The context manager runs the lifespan, so app.state is populated.
    with TestClient(app) as test_client:
        response = test_client.get("/healthz")

    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/problem+json")


def test_policy_is_loaded(pdp: str) -> None:
    """The fixture loaded the phase 6 policy and its data, so the alignment
    check has something to read from the next step onwards."""
    with httpx.Client(base_url=pdp, timeout=5.0) as opa:
        actions = opa.get("/v1/data/vo/authz/v5/_all_known_actions").json()
        policy = opa.get("/v1/data/vo/policy").json()

    assert "add_rule" in actions["result"]
    assert policy["result"]["known_rse_types"]

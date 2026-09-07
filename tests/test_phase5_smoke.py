"""
Phase 5 — smoke test against the full Rucio + OPA + Keycloak + PostgreSQL stack.

Same boundary as Phase 4's smoke tests, plus Keycloak `entitlements` claim
verification since Phase 5's whole privilege model depends on it. Does not
duplicate OPA policy content (entitlement privilege, self-service, root
bootstrap, runtime bundle overrides) — covered by tests/test_phase5_e2e.py.

rucio_call and rucio_opa_container_logs are shared helpers from conftest.py.
stack_urls/root_token are redefined locally (below), same pattern as
test_phase4_smoke.py, since this phase also needs the Keycloak URL that
Phase 2/3 don't.

Requires a running stack:
    cd phase5-opa/deploy
    docker compose --profile full up -d
    RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
        KEYCLOAK_URL=http://localhost:8080 \
        pytest tests/test_phase5_smoke.py -v

Skips automatically if the stack isn't reachable.
"""

import base64
import json
import os
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from conftest import RUCIO_ACCOUNT, RUCIO_PASSWORD, RUCIO_USERNAME
from conftest import rucio_call as _rucio_call
from conftest import rucio_opa_container_logs as _rucio_opa_container_logs

KEYCLOAK_CLIENT_ID = "rucio-oidc"
KEYCLOAK_CLIENT_SECRET = "rucio-oidc-secret"


# Local stack_urls / root_token — shadow conftest.py's versions for this
# module only, adding the Keycloak URL Phase 2/3 don't need.


@pytest.fixture(scope="module")
def stack_urls():
    rucio_url = os.environ.get("RUCIO_URL", "http://localhost").rstrip("/")
    opa_url = os.environ.get("OPA_URL", "http://localhost:8181").rstrip("/")
    keycloak_url = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")

    try:
        urlopen(f"{opa_url}/health", timeout=3)
    except URLError as exc:
        pytest.skip(f"OPA not reachable at {opa_url}: {exc}")

    try:
        with urlopen(f"{rucio_url}/ping", timeout=3) as resp:
            body = json.loads(resp.read())
        assert "version" in body
    except (URLError, AssertionError) as exc:
        pytest.skip(f"Rucio not reachable at {rucio_url}: {exc}")

    try:
        urlopen(f"{keycloak_url}/health/ready", timeout=3)
    except URLError as exc:
        pytest.skip(f"Keycloak not reachable at {keycloak_url}: {exc}")

    return rucio_url, opa_url, keycloak_url


@pytest.fixture(scope="module")
def root_token(stack_urls):
    rucio_url, _, _ = stack_urls
    req = Request(
        f"{rucio_url}/auth/userpass",
        headers={
            "X-Rucio-Account": RUCIO_ACCOUNT,
            "X-Rucio-Username": RUCIO_USERNAME,
            "X-Rucio-Password": RUCIO_PASSWORD,
        },
    )
    with urlopen(req, timeout=10) as resp:
        token = resp.headers.get("X-Rucio-Auth-Token")
    assert token, "Expected X-Rucio-Auth-Token header in auth response"
    return token


# Helpers unique to Phase 5 — Keycloak token issuance / JWT decode


def _keycloak_password_token(keycloak_url: str, username: str, password: str) -> str:
    """Obtain an access token via the Resource Owner Password grant."""
    body = urlencode(
        {
            "grant_type": "password",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "username": username,
            "password": password,
            "scope": "openid entitlements",
        }
    ).encode()
    req = Request(
        f"{keycloak_url}/realms/rucio/protocol/openid-connect/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read())
    token = payload.get("access_token")
    assert token, f"Expected access_token in Keycloak response, got: {payload}"
    return token


def _decode_jwt_claims(token: str) -> dict:
    """Decode a JWT's payload without verifying the signature (test-only)."""
    payload_segment = token.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# Keycloak — confirms entitlements is actually issued, since Phase 5's whole
# privilege model depends on it. This is real IdP behavior nothing else tests.
#
# Unlike Phase 4's wlcg.groups (nested under a "wlcg" claim namespace),
# entitlements is a flat top-level claim — confirmed against a live token:
#   {"entitlements": ["urn:...:group:rucio-users:role=member", ...]}


class TestKeycloakEntitlementsClaim:
    def test_alice_jwt_has_rucio_users_entitlement(self, stack_urls):
        _, _, keycloak_url = stack_urls
        token = _keycloak_password_token(keycloak_url, "alice", "alice123")
        claims = _decode_jwt_claims(token)
        entitlements = claims.get("entitlements", [])
        expected = "urn:example:aai.example.org:group:rucio-users:role=member"
        assert expected in entitlements, f"Expected {expected} in {entitlements}"

    def test_adminuser_jwt_has_rucio_admins_entitlement(self, stack_urls):
        _, _, keycloak_url = stack_urls
        token = _keycloak_password_token(keycloak_url, "adminuser", "admin123")
        claims = _decode_jwt_claims(token)
        entitlements = claims.get("entitlements", [])
        expected = "urn:example:aai.example.org:group:rucio-admins:role=member"
        assert expected in entitlements, f"Expected {expected} in {entitlements}"


# RSE management via root bootstrap — real Rucio REST calls, schema vs.
# policy rejection, same as Phase 2/3/4's smoke tests


class TestRseManagement:
    @pytest.mark.parametrize("rse", ["CERN_DATADISK", "BNL_TAPE", "DESY_SCRATCHDISK"])
    def test_create_valid_rse(self, stack_urls, root_token, rse):
        rucio_url, _, _ = stack_urls
        status, _ = _rucio_call(rucio_url, f"/rses/{rse}", root_token, "POST", {"rse_type": "DISK"})
        assert status in (201, 409)  # 409 if already created by a prior run

    def test_reject_unknown_rse_type_via_policy(self, stack_urls, root_token):
        """Well-formed but disallowed name — rejected by the OPA policy, not the schema."""
        rucio_url, _, _ = stack_urls
        status, _ = _rucio_call(
            rucio_url, "/rses/CERN_UNKNOWN", root_token, "POST", {"rse_type": "DISK"}
        )
        assert status == 401

    def test_list_rses(self, stack_urls, root_token):
        rucio_url, _, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/rses/", root_token)
        assert status == 200


# Wiring verification


class TestOpaWiring:
    def test_opa_authz_endpoint_was_hit(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "vo/authz/v4/allow" in logs, (
            "Expected Rucio to have called OPA's authz/v4/allow endpoint."
        )

    def test_opa_policy_was_loaded_via_rest(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "v1/policies/authz_v4" in logs, (
            "Expected the Rego policy to have been PUT to OPA on startup."
        )

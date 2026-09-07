"""
Phase 4 — smoke test against the full Rucio + OPA + Keycloak + PostgreSQL stack.

Same boundary as Phase 2/3's smoke tests: exercises real Rucio REST endpoints
(auth, schema validation, and that Rucio's policy-package hook actually calls
out to OPA end-to-end), and deliberately does NOT duplicate OPA policy-content
checks — group-based privilege, user self-service, root bootstrap, and
runtime group-policy bundle overrides are already covered by
tests4/test_phase4_e2e.py (Groups K/L/M/N).

    tests4/test_phase4_e2e.py -> policy content, via OPA directly
    this file                 -> wiring: Rucio API -> policy package -> OPA,
                                  plus that Keycloak actually issues the
                                  wlcg.groups claim Phase 4's privilege
                                  model depends on

Requires a running stack:
    cd phase4-opa/docker
    docker compose --profile full up -d
    RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
        KEYCLOAK_URL=http://localhost:8080 \
        pytest tests/test_phase4_smoke.py -v

Skips automatically if the stack isn't reachable.
"""

import base64
import json
import os
import shutil
import subprocess
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

RUCIO_ACCOUNT = "root"
RUCIO_USERNAME = "ddmlab"
RUCIO_PASSWORD = "secret"

KEYCLOAK_CLIENT_ID = "rucio-oidc"
KEYCLOAK_CLIENT_SECRET = "rucio-oidc-secret"


# ---------------------------------------------------------------------------
# Stack availability + auth fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stack_urls():
    """Resolve and verify Rucio + OPA + Keycloak are reachable, else skip the module."""
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rucio_call(rucio_url: str, path: str, token: str, method: str = "GET", json_body=None):
    """Return (status_code, response_bytes) for an authenticated Rucio API call."""
    data = json.dumps(json_body).encode() if json_body is not None else None
    headers = {"X-Rucio-Auth-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(f"{rucio_url}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def _keycloak_password_token(keycloak_url: str, username: str, password: str) -> str:
    """Obtain an access token via the Resource Owner Password grant."""
    body = urlencode(
        {
            "grant_type": "password",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "username": username,
            "password": password,
            "scope": "openid wlcg",
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


# ---------------------------------------------------------------------------
# Keycloak — confirms wlcg.groups is actually issued, since Phase 4's whole
# privilege model depends on it. This is real IdP behavior nothing else tests.
# ---------------------------------------------------------------------------


class TestKeycloakGroupsClaim:
    def test_alice_jwt_has_rucio_users_group(self, stack_urls):
        _, _, keycloak_url = stack_urls
        token = _keycloak_password_token(keycloak_url, "alice", "alice123")
        claims = _decode_jwt_claims(token)
        groups = claims.get("wlcg", {}).get("groups", [])
        assert "/rucio/users" in groups, f"Expected /rucio/users in {groups}"

    def test_adminuser_jwt_has_rucio_admins_group(self, stack_urls):
        _, _, keycloak_url = stack_urls
        token = _keycloak_password_token(keycloak_url, "adminuser", "admin123")
        claims = _decode_jwt_claims(token)
        groups = claims.get("wlcg", {}).get("groups", [])
        assert "/rucio/admins" in groups, f"Expected /rucio/admins in {groups}"


# ---------------------------------------------------------------------------
# RSE management via root bootstrap — real Rucio REST calls, schema vs.
# policy rejection, same as Phase 2/3's smoke tests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Wiring verification — proves Rucio actually calls OPA, not just that OPA
# answers correctly in isolation (that part is tests4/test_phase4_e2e.py)
# ---------------------------------------------------------------------------


def _rucio_opa_container_logs():
    """Return combined stdout+stderr of `docker logs rucio-opa`, or None if unavailable.

    OPA writes its structured access log to stderr, not stdout — both
    streams are checked. Returns None (rather than raising) when Docker
    isn't installed or the container isn't running, so callers can skip
    cleanly instead of failing on an environment precondition.
    """
    docker_path = shutil.which("docker")
    if not docker_path:
        return None
    result = subprocess.run(
        [docker_path, "logs", "rucio-opa"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return None
    return result.stdout + result.stderr


class TestOpaWiring:
    def test_opa_authz_endpoint_was_hit(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "vo/authz/v3/allow" in logs, (
            "Expected Rucio to have called OPA's authz/v3/allow endpoint."
        )

    def test_opa_policy_was_loaded_via_rest(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "v1/policies/authz_v3" in logs, (
            "Expected the Rego policy to have been PUT to OPA on startup."
        )

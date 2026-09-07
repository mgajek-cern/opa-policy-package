"""
Phase 3 — smoke test against the full Rucio + OPA + PostgreSQL stack.

Same boundary as Phase 2's smoke test: exercises real Rucio REST endpoints
over HTTP (auth, request routing, schema validation, and that Rucio's
policy-package hook actually calls out to OPA end-to-end), and deliberately
does NOT duplicate OPA policy-content checks — those are covered by
test_phase3_e2e.py (RSE naming, account/DID ownership, rule owner
self-service, protocol scheme allowlist, data-driven bundle overrides).

    test_phase3_opa.py    -> unit: input construction, fail-closed
    test_phase3_e2e.py    -> policy content, via OPA directly
    this file             -> wiring: Rucio API -> policy package -> OPA

Requires a running stack:
    cd phase3-opa/docker
    docker compose --profile full up -d
    RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
        pytest tests/test_phase3_smoke.py -v

Skips automatically if the stack isn't reachable.
"""

import json
import os
import shutil
import subprocess
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

RUCIO_ACCOUNT = "root"
RUCIO_USERNAME = "ddmlab"
RUCIO_PASSWORD = "secret"


# ---------------------------------------------------------------------------
# Stack availability + auth fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stack_urls():
    """Resolve and verify the Rucio + OPA stack is reachable, else skip the module."""
    rucio_url = os.environ.get("RUCIO_URL", "http://localhost").rstrip("/")
    opa_url = os.environ.get("OPA_URL", "http://localhost:8181").rstrip("/")

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

    return rucio_url, opa_url


@pytest.fixture(scope="module")
def auth_token(stack_urls):
    rucio_url, _ = stack_urls
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
# Helper: authenticated Rucio REST call
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


# ---------------------------------------------------------------------------
# RSE management — exercises schema validation vs. OPA policy rejection
# ---------------------------------------------------------------------------


class TestRseManagement:
    @pytest.mark.parametrize("rse", ["CERN_DATADISK", "BNL_TAPE", "DESY_SCRATCHDISK"])
    def test_create_valid_rse(self, stack_urls, auth_token, rse):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, f"/rses/{rse}", auth_token, "POST", {"rse_type": "DISK"})
        assert status in (201, 409)  # 409 if already created by a prior run

    @pytest.mark.parametrize("rse", ["cern_bad", "lowercase_rse"])
    def test_reject_invalid_rse_name_at_schema_level(self, stack_urls, auth_token, rse):
        """Rucio's REST schema itself rejects malformed identifiers — before policy runs."""
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, f"/rses/{rse}", auth_token, "POST", {"rse_type": "DISK"})
        assert status == 400

    def test_reject_unknown_rse_type_via_policy(self, stack_urls, auth_token):
        """Well-formed but disallowed name — rejected by the OPA policy, not the schema."""
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(
            rucio_url, "/rses/CERN_UNKNOWN", auth_token, "POST", {"rse_type": "DISK"}
        )
        assert status == 401

    def test_list_rses(self, stack_urls, auth_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/rses/", auth_token)
        assert status == 200


# ---------------------------------------------------------------------------
# Wiring verification — proves Rucio actually calls OPA, not just that OPA
# answers correctly in isolation (that part is test_phase3_e2e.py)
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
    # S603: fixed, hardcoded argument list — no untrusted input reaches
    # this call. Executable path is fully resolved via shutil.which (S607).
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
        assert "vo/authz/v2/allow" in logs, (
            "Expected Rucio to have called OPA's authz/v2/allow endpoint."
        )

    def test_opa_policy_was_loaded_via_rest(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "v1/policies/authz_v2" in logs, (
            "Expected the Rego policy to have been PUT to OPA on startup."
        )

"""
Fixtures shared by the test modules. Plain helpers live in helpers.py.

Several fixtures read module-level settings, so a test module configures
them by declaring constants rather than redefining fixtures:

    REGO_PATH          opa_server spawns `opa` on it when OPA_URL is unset
    OPA_POLICY_PATH    presence turns on the autouse OPA client redirect
    CLAIM_POLICY_PATH  data document claim_policy overrides and restores
    AUTHZ_SCOPE        scope the persona token fixtures request
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess

import pytest

from helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    DEFAULT_AUTHZ_SCOPE,
    DEP_END_USER_PASSWORD,
    DEP_END_USER_USERNAME,
    DEP_OPERATOR_PASSWORD,
    DEP_OPERATOR_USERNAME,
    MODEL_DEVELOPER_PASSWORD,
    MODEL_DEVELOPER_USERNAME,
    OIDC_EXPECTED_SCOPE,
    OIDC_GRANT_TYPE,
    OIDC_PASSWORD,
    OIDC_TEAPOT_AUD_SCOPE,
    OIDC_USERNAME,
    RUCIO_AUTH,
    TEAPOT1_URL,
    TEAPOT2_URL,
    USER_PASSWORD,
    USER_USERNAME,
    client_credentials_token,
    free_port,
    mint,
    opa_delete,
    opa_get,
    opa_healthy,
    opa_put,
    password_token,
    rse_resource,
    stack_unreachable,
    userpass_token,
    wait_for_port,
    webdav_warm_up,
)

# ── OPA ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def opa_server(request):
    """OPA for the requesting module.

    `make test-opa` exports OPA_URL, so this normally reuses the testbed's
    own OPA — whose bundle is why every fixture that writes to it restores
    what was there. With OPA_URL empty it spawns `opa` on the module's
    REGO_PATH instead, which needs the binary on PATH.
    """
    external_url = os.environ.get("OPA_URL", "").strip()
    if external_url:
        if not opa_healthy(external_url):
            pytest.skip(f"OPA_URL={external_url} is not reachable")
        yield external_url
        return

    rego_path = getattr(request.module, "REGO_PATH", None)
    if rego_path is None:
        pytest.skip("OPA_URL is not set and the module declares no REGO_PATH")

    opa_path = shutil.which("opa")
    if not opa_path:
        pytest.skip("'opa' binary not found on PATH and OPA_URL is not set")

    port = free_port()
    proc = subprocess.Popen(
        [
            opa_path,
            "run",
            "--server",
            "--log-level",
            "error",
            f"--addr=127.0.0.1:{port}",
            str(rego_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_port(port):
            pytest.skip(f"OPA did not start on port {port}")
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


@pytest.fixture(autouse=True)
def _point_opa_client(request, monkeypatch):
    """Aim the policy package's OPA client at opa_server, in OPA modules only."""
    policy_path = getattr(request.module, "OPA_POLICY_PATH", None)
    if policy_path is None:
        return
    monkeypatch.setenv("OPA_URL", request.getfixturevalue("opa_server"))
    monkeypatch.setenv("OPA_POLICY_PATH", policy_path)


def _override_document(opa_url: str, path: str):
    """Let a test replace one data document, then restore whatever was there."""
    saved = opa_get(opa_url, path)
    written = False

    def _set(value) -> None:
        nonlocal written
        written = True
        opa_put(opa_url, path, value)

    yield _set

    if written:
        if saved is None:
            opa_delete(opa_url, path)
        else:
            opa_put(opa_url, path, saved)


@pytest.fixture
def claim_policy(request, opa_server):
    """Replace the module's claim → privilege mapping for one test.

    The module's CLAIM_POLICY_PATH names it: vo/group_policy in phase 4,
    vo/entitlement_policy from phase 5. Without the restore, the suite leaves
    the testbed's bundle rewritten and its admins unprivileged, which shows up
    as an unrelated failure in the Rucio suite on the next run.
    """
    yield from _override_document(opa_server, request.module.CLAIM_POLICY_PATH)


@pytest.fixture
def policy_leaf(opa_server):
    """Set data.vo.policy leaves for one test, then put back what was there.

    Restoring rather than deleting matters: deleting would strip a leaf the
    testbed's own bundle sets.
    """
    saved = {}

    def _set(leaf: str, value) -> None:
        saved.setdefault(leaf, opa_get(opa_server, f"vo/policy/{leaf}"))
        opa_put(opa_server, f"vo/policy/{leaf}", value)

    yield _set

    for leaf, previous in saved.items():
        if previous is None:
            opa_delete(opa_server, f"vo/policy/{leaf}")
        else:
            opa_put(opa_server, f"vo/policy/{leaf}", previous)


# ── Rucio authorisation: personas ─────────────────────────────────────────


@pytest.fixture(scope="module")
def require_rucio():
    """Skip the module when Rucio (and Keycloak, if KEYCLOAK_URL is set) is down."""
    reason = stack_unreachable()
    if reason:
        pytest.skip(reason)


def _authz_scope(request) -> str:
    return os.environ.get("OIDC_AUTHZ_SCOPE") or getattr(
        request.module, "AUTHZ_SCOPE", DEFAULT_AUTHZ_SCOPE
    )


@pytest.fixture(scope="module")
def admin_token(request):
    return password_token(ADMIN_USERNAME, ADMIN_PASSWORD, _authz_scope(request))


@pytest.fixture(scope="module")
def user_token(request):
    return password_token(USER_USERNAME, USER_PASSWORD, _authz_scope(request))


@pytest.fixture(scope="module")
def dep_operator_token(request):
    return password_token(DEP_OPERATOR_USERNAME, DEP_OPERATOR_PASSWORD, _authz_scope(request))


@pytest.fixture(scope="module")
def dep_end_user_token(request):
    return password_token(DEP_END_USER_USERNAME, DEP_END_USER_PASSWORD, _authz_scope(request))


@pytest.fixture(scope="module")
def model_developer_token(request):
    return password_token(MODEL_DEVELOPER_USERNAME, MODEL_DEVELOPER_PASSWORD, _authz_scope(request))


# ── Transfers (phase 6) ───────────────────────────────────────────────────


@pytest.fixture(scope="session")
def rucio_token() -> str:
    """Bearer token for Rucio REST calls in the transfer suite.

    Defaults to userpass-as-root, which the Rego short-circuits — right for a
    suite that tests transfers rather than authorisation. The claims path is
    covered by test_phase6_rucio.py. RUCIO_AUTH=oidc runs it token-natively.
    """
    if RUCIO_AUTH == "oidc":
        return password_token(
            ADMIN_USERNAME,
            ADMIN_PASSWORD,
            os.environ.get("OIDC_AUTHZ_SCOPE") or DEFAULT_AUTHZ_SCOPE,
        )
    return userpass_token()


@pytest.fixture(scope="session")
def oidc_token():
    return mint(OIDC_EXPECTED_SCOPE, resource=rse_resource("xrd4"))


@pytest.fixture(scope="session")
def teapot_token():
    """One token used against both Teapots, so it must carry both audiences.

    On Keycloak the audience comes from the aud:teapot* client scopes; on
    LS AAI/EGI that syntax is invalid_scope and resource= carries it instead.
    """
    if OIDC_GRANT_TYPE == "client_credentials":
        return client_credentials_token(
            scope=OIDC_EXPECTED_SCOPE,
            resource=[rse_resource("teapot1"), rse_resource("teapot2")],
        )
    scope = " ".join(filter(None, [OIDC_EXPECTED_SCOPE, OIDC_TEAPOT_AUD_SCOPE]))
    return password_token(OIDC_USERNAME, OIDC_PASSWORD, scope=scope)


@pytest.fixture(scope="session")
def teapots_ready(teapot_token):
    """Warm up both Teapot Storm-WebDAV JVMs before transfer tests."""
    webdav_warm_up(TEAPOT1_URL, "/data/", "teapot1", teapot_token)
    webdav_warm_up(TEAPOT2_URL, "/data/", "teapot2", teapot_token)
    return True


@pytest.fixture(scope="session")
def xrd3_write_token():
    return mint(OIDC_EXPECTED_SCOPE, resource=rse_resource("xrd3"))


@pytest.fixture(scope="session")
def xrd4_write_token():
    return mint(OIDC_EXPECTED_SCOPE, resource=rse_resource("xrd4"))

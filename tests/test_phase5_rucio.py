"""
Phase 5 — exercises the OIDC → has_permission() → OPA path with real tokens.

The half the smoke tests don't cover: test_phase5_smoke.py mints a token and
decodes it locally, proving the IdP issues the claim; test_phase5_e2e.py
POSTs handcrafted documents to OPA, proving the Rego evaluates them. Neither
sends a token to Rucio. This does.

The positive test is the regression guard for the claims plumbing
(patches/rucio/: authentication.py, oidc.py, types.py, common.py). The
negative test would also pass with that plumbing reverted, since empty
claims deny too — read them as a pair, and don't delete the positive one.

Uses REST rather than the Rucio client: auth_type=oidc drives an interactive
browser flow. REST also surfaces ExceptionClass/ExceptionMessage, which is
what distinguishes a policy deny from a rejected token — both are 401.

Requires scripts/init-phase5.sh to have run: without the identity mapping,
validate_jwt cannot resolve a token to an account and every test here fails
with CannotAuthenticate.
"""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

KEYCLOAK_CLIENT_ID = "rucio-oidc"
KEYCLOAK_CLIENT_SECRET = "rucio-oidc-secret"

# Must match AUTHZ_TEST_USERS in scripts/init-phase5.sh.
ADMIN_USERNAME = os.environ.get("OIDC_ADMIN_USERNAME", "adminuser")
ADMIN_PASSWORD = os.environ.get("OIDC_ADMIN_PASSWORD", "admin123")
USER_USERNAME = os.environ.get("OIDC_USER_USERNAME", "alice")
USER_PASSWORD = os.environ.get("OIDC_USER_PASSWORD", "alice123")

# Superset of [oidc] expected_scope in configs/rucio/phase5/rucio.cfg, plus
# aud:rucio to satisfy expected_audience. A token missing either is rejected
# by validate_jwt before has_permission() runs.
AUTHZ_SCOPE = os.environ.get("OIDC_AUTHZ_SCOPE", "openid offline_access aud:rucio")

# Created by the smoke tests; CERN_DATADISK passes the Rego naming rule, so a
# deny on it is unambiguously a privilege decision.
VALID_RSE = "CERN_DATADISK"
BAD_NAME_RSE = "CERN_UNKNOWN"


@pytest.fixture(scope="module")
def stack_urls():
    rucio_url = os.environ.get("RUCIO_URL", "http://localhost").rstrip("/")
    keycloak_url = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")

    try:
        with urlopen(f"{rucio_url}/ping", timeout=3) as resp:
            assert "version" in json.loads(resp.read())
    except (URLError, AssertionError) as exc:
        pytest.skip(f"Rucio not reachable at {rucio_url}: {exc}")

    try:
        urlopen(f"{keycloak_url}/health/ready", timeout=3)
    except URLError as exc:
        pytest.skip(f"Keycloak not reachable at {keycloak_url}: {exc}")

    return rucio_url, keycloak_url


def _token(keycloak_url: str, username: str, password: str) -> str:
    body = urlencode(
        {
            "grant_type": "password",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "username": username,
            "password": password,
            "scope": AUTHZ_SCOPE,
        }
    ).encode()
    req = Request(
        f"{keycloak_url}/realms/rucio/protocol/openid-connect/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


@pytest.fixture(scope="module")
def admin_token(stack_urls):
    _, keycloak_url = stack_urls
    return _token(keycloak_url, ADMIN_USERNAME, ADMIN_PASSWORD)


@pytest.fixture(scope="module")
def user_token(stack_urls):
    _, keycloak_url = stack_urls
    return _token(keycloak_url, USER_USERNAME, USER_PASSWORD)


def _call(rucio_url, path, token, method="GET", body=None):
    """Return (status, ExceptionClass, ExceptionMessage)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-Rucio-Auth-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"

    req = Request(f"{rucio_url}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as resp:
            return (
                resp.status,
                resp.headers.get("ExceptionClass"),
                resp.headers.get("ExceptionMessage"),
            )
    except HTTPError as exc:
        return exc.code, exc.headers.get("ExceptionClass"), exc.headers.get("ExceptionMessage")


# Entitlement-driven privilege
#
# adminuser holds rucio-admins, which data.vo.entitlement_policy maps to
# "admin"; alice holds rucio-users, which maps to "user" — and since
# _is_privileged only ever compares against "admin", alice reaches the same
# clauses as an account with no entitlements at all.


class TestEntitlementAuthorisation:
    def test_admin_entitlement_allows_add_rse(self, stack_urls, admin_token):
        """rucio-admins → admin → _is_privileged → allow."""
        rucio_url, _ = stack_urls
        status, exc_cls, exc_msg = _call(
            rucio_url, f"/rses/{VALID_RSE}", admin_token, "POST", {"rse_type": "DISK"}
        )
        # 409 means the RSE already exists — the policy allowed the call.
        assert status in (201, 409), (
            f"HTTP {status} {exc_cls}: {exc_msg} — CannotAuthenticate means the "
            "token was rejected before the policy ran; check [oidc] "
            "expected_scope/expected_audience and that init-phase5.sh has run"
        )

    def test_user_entitlement_denies_add_rse(self, stack_urls, user_token):
        """rucio-users → not privileged → deny."""
        rucio_url, _ = stack_urls
        status, exc_cls, exc_msg = _call(
            rucio_url, f"/rses/{VALID_RSE}", user_token, "POST", {"rse_type": "DISK"}
        )
        assert status in (401, 403), f"HTTP {status} {exc_cls}: {exc_msg}"
        assert exc_cls == "AccessDenied", (
            f"{exc_cls}: {exc_msg} — AccessDenied means the policy denied; "
            "CannotAuthenticate means the token never reached it"
        )

    def test_admin_entitlement_denies_bad_rse_name(self, stack_urls, admin_token):
        """Naming rule runs regardless of privilege — _perm_add_rse needs both."""
        rucio_url, _ = stack_urls
        status, exc_cls, _ = _call(
            rucio_url, f"/rses/{BAD_NAME_RSE}", admin_token, "POST", {"rse_type": "DISK"}
        )
        assert status in (401, 403)
        assert exc_cls == "AccessDenied"

    def test_admin_entitlement_allows_del_rse_attribute(self, stack_urls, admin_token):
        """del_rse_attribute is privileged-only with no domain check."""
        rucio_url, _ = stack_urls
        status, exc_cls, exc_msg = _call(
            rucio_url, f"/rses/{VALID_RSE}/attr/nonexistent", admin_token, "DELETE"
        )
        # The attribute doesn't exist, so expect a not-found rather than a
        # policy deny — what matters is that it isn't AccessDenied.
        assert exc_cls != "AccessDenied", f"HTTP {status} {exc_cls}: {exc_msg}"

    def test_user_entitlement_denies_del_rse_attribute(self, stack_urls, user_token):
        rucio_url, _ = stack_urls
        status, exc_cls, exc_msg = _call(
            rucio_url, f"/rses/{VALID_RSE}/attr/nonexistent", user_token, "DELETE"
        )
        assert exc_cls == "AccessDenied", f"HTTP {status} {exc_cls}: {exc_msg}"


# Self-service — the ownership clauses, which gate on kwargs matching the
# issuer rather than on entitlements. These would pass for any authenticated
# account, so they test the Rego's logic rather than the claims plumbing.


class TestSelfService:
    def test_user_can_create_did_in_own_scope(self, stack_urls, user_token):
        """startswith(kwargs.scope, issuer) → allow. alice owns scope 'alice'."""
        import time

        rucio_url, _ = stack_urls
        name = f"selfservice-{int(time.time() * 1000)}"
        status, exc_cls, exc_msg = _call(
            rucio_url,
            f"/dids/{USER_USERNAME}/{name}",
            user_token,
            "POST",
            {"type": "DATASET"},
        )
        assert status == 201, f"HTTP {status} {exc_cls}: {exc_msg}"

    def test_user_cannot_create_did_in_foreign_scope(self, stack_urls, user_token):
        """Scope owned by another account → no ownership clause matches → deny."""
        import time

        rucio_url, _ = stack_urls
        name = f"foreign-{int(time.time() * 1000)}"
        status, exc_cls, exc_msg = _call(
            rucio_url,
            f"/dids/adminuser/{name}",
            user_token,
            "POST",
            {"type": "DATASET"},
        )
        assert status in (401, 403), f"HTTP {status} {exc_cls}: {exc_msg}"
        assert exc_cls == "AccessDenied", f"{exc_cls}: {exc_msg}"

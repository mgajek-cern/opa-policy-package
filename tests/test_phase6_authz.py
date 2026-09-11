"""
Exercises the OIDC → has_permission() → OPA path with real tokens.

The positive test is the regression guard for the claims plumbing
(patches/rucio/: authentication.py, oidc.py, types.py, common.py). The
negative test would also pass with that plumbing reverted, since empty
claims deny too — read them as a pair, and don't delete the positive one.

Uses REST rather than the Rucio client: auth_type=oidc drives an
interactive browser flow, and the non-interactive alternative (pre-writing
the client's token cache) depends on a path derived from get_tmp_dir() and
the account name. REST also surfaces ExceptionClass/ExceptionMessage
headers, so a failure says why.
"""

import os

import pytest

from conftest import (
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_TOKEN_URL,
    deny_reason,
    fetch_token_password,
    rucio_rest,
)

# Must match AUTHZ_TEST_USERS in scripts/init-testbed.sh.
ADMIN_USERNAME = os.environ.get("OIDC_ADMIN_USERNAME", "adminuser")
ADMIN_PASSWORD = os.environ.get("OIDC_ADMIN_PASSWORD", "admin123")
USER_USERNAME = os.environ.get("OIDC_USER_USERNAME", "randomaccount")
USER_PASSWORD = os.environ.get("OIDC_USER_PASSWORD", "secret")

# Superset of the server's [oidc] expected_scope, plus aud:rucio to satisfy
# expected_audience. A token missing either is rejected by validate_jwt with
# 401 before has_permission() runs.
AUTHZ_SCOPE = os.environ.get(
    "OIDC_AUTHZ_SCOPE",
    "openid offline_access storage.read:/ storage.modify:/ aud:rucio",
)

# set_local_account_limit is gated purely on _is_privileged — it is not in
# _all_known_actions, so it falls to the catch-all. Idempotent, and unlike
# add_rse it isn't also subject to the phase 6 RSE-name allowlist, so a deny
# is unambiguously an entitlement decision.
PRIVILEGED_PATH = "/accounts/ddmlab/limits/local/XRD3"
PRIVILEGED_BODY = {"bytes": -1}


def _token(username, password):
    return fetch_token_password(
        OIDC_TOKEN_URL,
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET,
        username,
        password,
        scope=AUTHZ_SCOPE,
    )


@pytest.fixture(scope="session")
def admin_token():
    return _token(ADMIN_USERNAME, ADMIN_PASSWORD)


@pytest.fixture(scope="session")
def user_token():
    return _token(USER_USERNAME, USER_PASSWORD)


class TestEntitlementAuthorisation:
    def test_admin_entitlement_allows_privileged_action(self, admin_token):
        """rucio-admins → admin in the bundle → _is_privileged → allow."""
        resp = rucio_rest(PRIVILEGED_PATH, admin_token, "POST", PRIVILEGED_BODY)
        assert resp.status_code in (200, 201), (
            f"HTTP {resp.status_code} {deny_reason(resp)} — if this is "
            "CannotAuthenticate the token was rejected before the policy ran; "
            "check [oidc] expected_scope/expected_audience against AUTHZ_SCOPE"
        )

    def test_user_entitlement_denies_privileged_action(self, user_token):
        """rucio-users → user → not privileged → deny."""
        resp = rucio_rest(PRIVILEGED_PATH, user_token, "POST", PRIVILEGED_BODY)
        assert resp.status_code in (401, 403), f"HTTP {resp.status_code}"
        exc_cls, exc_msg = deny_reason(resp)
        assert exc_cls == "AccessDenied", (
            f"{exc_cls}: {exc_msg} — AccessDenied means the policy denied; "
            "CannotAuthenticate means the token never reached it"
        )

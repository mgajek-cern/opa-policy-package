"""
Exercises the OIDC → has_permission() → OPA path with real tokens.
"""

import os
import time

import pytest

from conftest import (
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_TOKEN_URL,
    deny_reason,
    fetch_token_password,
    rucio_rest,
)

# Must match AUTHZ_TEST_USERS in scripts/init-phase6.sh.
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

# Scopes created by scripts/init-phase6.sh. The last two are what make the
# ownership tests meaningful: one the user owns but is not named after, and
# one whose name starts with the user's but belongs to ddmlab.
OWNED_SCOPE = USER_USERNAME
OWNED_SCOPE_UNNAMED = "projectdata"
FOREIGN_SCOPE_PREFIXED = "randomaccountleak"
FOREIGN_SCOPE = "ddmlab"


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


def _did_name(prefix):
    return f"{prefix}-{int(time.time() * 1000)}"


# TestEntitlementAuthorisation covers the privileged path — an entitlement
# that maps to "admin" in the bundle. TestScopeOwnership covers the
# ownership clauses, which gate on kwargs.owned_scopes rather than on
# entitlements; those would pass for any authenticated account and test the
# Rego plus the scopes-table lookup rather than the claims plumbing.


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


# Scope ownership
#
# permission.py resolves kwargs.owned_scopes from the scopes table and the
# Rego compares against it. The two middle cases are the ones the old name
# prefix check got wrong; they are the reason this is a DB lookup.


class TestScopeOwnership:
    def test_user_can_create_did_in_own_scope(self, user_token):
        name = _did_name("selfservice")
        resp = rucio_rest(f"/dids/{OWNED_SCOPE}/{name}", user_token, "POST", {"type": "DATASET"})
        assert resp.status_code == 201, f"HTTP {resp.status_code} {deny_reason(resp)}"

    def test_user_can_create_did_in_owned_scope_not_named_after_account(self, user_token):
        """Owned via the scopes table, denied by any name-based check."""
        name = _did_name("unnamed")
        resp = rucio_rest(
            f"/dids/{OWNED_SCOPE_UNNAMED}/{name}", user_token, "POST", {"type": "DATASET"}
        )
        assert resp.status_code == 201, (
            f"HTTP {resp.status_code} {deny_reason(resp)} — is "
            f"'{OWNED_SCOPE_UNNAMED}' registered to {USER_USERNAME}? "
            "scripts/init-phase6.sh adds it."
        )

    def test_user_cannot_create_did_in_foreign_scope_sharing_its_prefix(self, user_token):
        """Owned by ddmlab; a prefix check would have allowed this."""
        name = _did_name("prefixleak")
        resp = rucio_rest(
            f"/dids/{FOREIGN_SCOPE_PREFIXED}/{name}", user_token, "POST", {"type": "DATASET"}
        )
        assert resp.status_code in (401, 403), f"HTTP {resp.status_code}"
        assert deny_reason(resp)[0] == "AccessDenied", deny_reason(resp)

    def test_user_cannot_create_did_in_foreign_scope(self, user_token):
        name = _did_name("foreign")
        resp = rucio_rest(f"/dids/{FOREIGN_SCOPE}/{name}", user_token, "POST", {"type": "DATASET"})
        assert resp.status_code in (401, 403), f"HTTP {resp.status_code}"
        assert deny_reason(resp)[0] == "AccessDenied", deny_reason(resp)

    def test_admin_can_create_did_in_any_scope(self, admin_token):
        """Privilege short-circuits ownership."""
        name = _did_name("adminforeign")
        resp = rucio_rest(f"/dids/{FOREIGN_SCOPE}/{name}", admin_token, "POST", {"type": "DATASET"})
        assert resp.status_code == 201, f"HTTP {resp.status_code} {deny_reason(resp)}"


class TestBulkScopeOwnership:
    """add_dids and attach_dids_to_dids carry scopes nested in a list.

    Worth exercising over REST: the nested InternalScope objects have to
    survive serialisation into the OPA input, which a top-level-only unwrap
    does not manage — the request then fails closed before OPA sees it.
    """

    def test_bulk_add_in_owned_scopes(self, user_token):
        ts = int(time.time() * 1000)
        resp = rucio_rest(
            "/dids",
            user_token,
            "POST",
            [
                {"scope": OWNED_SCOPE, "name": f"bulk-a-{ts}", "type": "DATASET"},
                {"scope": OWNED_SCOPE_UNNAMED, "name": f"bulk-b-{ts}", "type": "DATASET"},
            ],
        )
        assert resp.status_code in (201, 409), f"HTTP {resp.status_code} {deny_reason(resp)}"

    def test_bulk_add_denied_when_one_scope_is_foreign(self, user_token):
        ts = int(time.time() * 1000)
        resp = rucio_rest(
            "/dids",
            user_token,
            "POST",
            [
                {"scope": OWNED_SCOPE, "name": f"bulk-c-{ts}", "type": "DATASET"},
                {"scope": FOREIGN_SCOPE, "name": f"bulk-d-{ts}", "type": "DATASET"},
            ],
        )
        assert resp.status_code in (401, 403), f"HTTP {resp.status_code}"
        assert deny_reason(resp)[0] == "AccessDenied", deny_reason(resp)


# Rule self-service — gates on kwargs.account, two account names the gateway
# already resolved. No scopes table involved.


class TestRuleSelfService:
    def test_user_can_add_rule_for_own_account(self, user_token):
        """kwargs.account == issuer and locked == false → allow."""
        name = _did_name("ownrule")
        rucio_rest(f"/dids/{OWNED_SCOPE}/{name}", user_token, "POST", {"type": "DATASET"})
        resp = rucio_rest(
            "/rules/",
            user_token,
            "POST",
            {
                "dids": [{"scope": OWNED_SCOPE, "name": name}],
                "copies": 1,
                "rse_expression": "XRD4",
                "account": USER_USERNAME,
            },
        )
        assert resp.status_code == 201, f"HTTP {resp.status_code} {deny_reason(resp)}"

    def test_user_cannot_add_rule_for_another_account(self, user_token):
        """kwargs.account != issuer and not privileged → deny.

        Rucio returns 500 rather than 401 here: POST /rules/ doesn't
        translate the AccessDenied raised for a mismatched account, so
        ErrorHandlingMethodView catches it as an untranslated RucioException.
        The policy denies correctly — visible in the OPA input log — so the
        assertion is "the rule was not created" rather than a status code.
        Tighten this to (401, 403) if a future Rucio fixes the translation.
        """
        name = _did_name("otherrule")
        rucio_rest(f"/dids/{OWNED_SCOPE}/{name}", user_token, "POST", {"type": "DATASET"})
        resp = rucio_rest(
            "/rules/",
            user_token,
            "POST",
            {
                "dids": [{"scope": OWNED_SCOPE, "name": name}],
                "copies": 1,
                "rse_expression": "XRD4",
                "account": "ddmlab",
            },
        )
        assert resp.status_code != 201, f"rule was created for another account: {resp.text[:200]}"

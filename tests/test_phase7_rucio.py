"""
Phase 7 — exercises the OIDC → has_permission() → authz-service → OPA path
with real tokens.

Unlike test_phase6_rucio.py, permission.py here calls authz-service over
HTTP via a generated client (rucio_authz_client, openapi-generator's
python-legacy target — see services/authorization-service/docs/
python39-constraint.md for why this generator specifically, over
openapi-python-client, given rucio-server's Python 3.9 pin). This file
exercises the full chain through real Rucio REST calls; it doesn't (and
can't, since opa_client.py is gone) query OPA directly the way
test_phase7_opa.py's predecessor did.
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

ADMIN_USERNAME = os.environ.get("OIDC_ADMIN_USERNAME", "adminuser")
ADMIN_PASSWORD = os.environ.get("OIDC_ADMIN_PASSWORD", "admin123")
USER_USERNAME = os.environ.get("OIDC_USER_USERNAME", "randomaccount")
USER_PASSWORD = os.environ.get("OIDC_USER_PASSWORD", "secret")

# Same scope requirement as phase 6 — this token authenticates the caller
# to rucio-server. permission.py separately obtains its own authz-service-
# scoped token per request (get_token_for_account_operation), which is
# independent of what's requested here.
AUTHZ_SCOPE = os.environ.get(
    "OIDC_AUTHZ_SCOPE",
    "openid offline_access storage.read:/ storage.modify:/ aud:rucio",
)

PRIVILEGED_PATH = "/accounts/ddmlab/limits/local/XRD3"
PRIVILEGED_BODY = {"bytes": -1}

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


class TestEntitlementAuthorisation:
    def test_admin_entitlement_allows_privileged_action(self, admin_token):
        resp = rucio_rest(PRIVILEGED_PATH, admin_token, "POST", PRIVILEGED_BODY)
        assert resp.status_code in (200, 201), (
            f"HTTP {resp.status_code} {deny_reason(resp)} — if this is "
            "CannotAuthenticate the token was rejected before has_permission() "
            "ran; if it's a 5xx from authz-service being unreachable, check "
            "AUTHZ_SERVICE_URL and that the rucio->authz-service token "
            "exchange grant has been run against this Keycloak"
        )

    def test_user_entitlement_denies_privileged_action(self, user_token):
        resp = rucio_rest(PRIVILEGED_PATH, user_token, "POST", PRIVILEGED_BODY)
        assert resp.status_code in (401, 403), f"HTTP {resp.status_code}"
        exc_cls, exc_msg = deny_reason(resp)
        assert exc_cls == "AccessDenied", (
            f"{exc_cls}: {exc_msg} — AccessDenied means authz-service denied; "
            "CannotAuthenticate means the token never reached has_permission()"
        )


class TestScopeOwnership:
    def test_user_can_create_did_in_own_scope(self, user_token):
        name = _did_name("selfservice")
        resp = rucio_rest(f"/dids/{OWNED_SCOPE}/{name}", user_token, "POST", {"type": "DATASET"})
        assert resp.status_code == 201, f"HTTP {resp.status_code} {deny_reason(resp)}"

    def test_user_can_create_did_in_owned_scope_not_named_after_account(self, user_token):
        name = _did_name("unnamed")
        resp = rucio_rest(
            f"/dids/{OWNED_SCOPE_UNNAMED}/{name}", user_token, "POST", {"type": "DATASET"}
        )
        assert resp.status_code == 201, (
            f"HTTP {resp.status_code} {deny_reason(resp)} — is "
            f"'{OWNED_SCOPE_UNNAMED}' registered to {USER_USERNAME}?"
        )

    def test_user_cannot_create_did_in_foreign_scope_sharing_its_prefix(self, user_token):
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
        name = _did_name("adminforeign")
        resp = rucio_rest(f"/dids/{FOREIGN_SCOPE}/{name}", admin_token, "POST", {"type": "DATASET"})
        assert resp.status_code == 201, f"HTTP {resp.status_code} {deny_reason(resp)}"


class TestBulkScopeOwnership:
    """add_dids/attach_dids_to_dids carry scopes nested in a list — worth
    exercising over REST since permission.py resolves ownership per DID
    (_scope_owner) before authz-service ever sees the request; a bug there
    fails closed before the Rego runs at all."""

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


class TestRuleSelfService:
    def test_user_can_add_rule_for_own_account(self, user_token):
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


class TestAuthzServiceUnreachable:
    """New in phase 8 (no equivalent in phase 6/direct-OPA phase 7): the
    hop through authz-service means a network failure between rucio-server
    and authz-service is now a distinct failure mode from Rego denying,
    and it must fail closed the same way. Requires the test runner to be
    able to stop the authz-service container — skip if not applicable to
    this environment."""

    @pytest.mark.skip(reason="requires container control from the test runner — run manually")
    def test_request_denied_when_authz_service_unreachable(self, user_token):
        # docker stop compose-authz-service-1, run the assertion below,
        # docker start compose-authz-service-1 — see authz_client.py's
        # fail-closed contract in permission.py's has_permission(): any
        # exception from the generated client's call (including
        # ApiException and connection errors) is caught and denies.
        name = _did_name("outage")
        resp = rucio_rest(f"/dids/{OWNED_SCOPE}/{name}", user_token, "POST", {"type": "DATASET"})
        assert resp.status_code in (401, 403), (
            f"authz-service outage must deny, not silently permit: got {resp.status_code}"
        )

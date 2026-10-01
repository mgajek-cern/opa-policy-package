"""
Authorisation contracts exercised over Rucio's REST API with real tokens.

Shared by test_phase4_rucio.py, test_phase5_rucio.py, test_phase6_rucio.py
and test_phase6_rucio_authz_service.py. The token fixtures (admin_token,
user_token, the DEP personas) come from conftest.py; the accounts and scopes
below are what the phase's init script creates.

Every deny assertion checks ExceptionClass, not just the status: AccessDenied
means the policy denied, CannotAuthenticate means the token never reached
has_permission() — usually a scope/audience mismatch against [oidc]
expected_scope/expected_audience. Both come back as 401.

Nothing here is collected on its own: pytest only collects Test* classes.
"""

from __future__ import annotations

from helpers import (
    USER_USERNAME,
    deny_reason,
    rucio_rest,
    unique,
)

AUTH_HINT = (
    " — CannotAuthenticate means the token was rejected before the policy ran; "
    "check [oidc] expected_scope/expected_audience and that the init script has run"
)


def create_dataset(token: str, scope: str, prefix: str):
    return rucio_rest(f"/dids/{scope}/{unique(prefix)}", token, "POST", {"type": "DATASET"})


def assert_allowed(resp, ok=(200, 201), hint: str = "") -> None:
    assert resp.status_code in ok, f"HTTP {resp.status_code} {deny_reason(resp)}{hint}"


def assert_denied(resp) -> None:
    assert resp.status_code in (401, 403), f"HTTP {resp.status_code} {deny_reason(resp)}"
    assert deny_reason(resp)[0] == "AccessDenied", (
        f"{deny_reason(resp)} — AccessDenied means the policy denied; "
        "CannotAuthenticate means the token never reached it"
    )


class RucioIdentities:
    """Scopes from the init script: one the user owns and is named after, one
    it owns but isn't, and a foreign one whose name starts with the user's —
    the two middle cases are what a name-prefix check gets wrong."""

    OWNED_SCOPE = USER_USERNAME
    OWNED_SCOPE_UNNAMED = "projectdata"
    FOREIGN_SCOPE_PREFIXED = "randomaccountleak"
    FOREIGN_SCOPE = "ddmlab"
    OTHER_ACCOUNT = "ddmlab"


# ── Scope ownership (every phase) ─────────────────────────────────────────


class ScopeOwnershipContract(RucioIdentities):
    """permission.py resolves kwargs.owned_scopes from the scopes table; the
    Rego compares against it."""

    def test_user_can_create_did_in_own_scope(self, user_token):
        assert_allowed(create_dataset(user_token, self.OWNED_SCOPE, "selfservice"), ok=(201,))

    def test_user_can_create_did_in_owned_scope_not_named_after_account(self, user_token):
        resp = create_dataset(user_token, self.OWNED_SCOPE_UNNAMED, "unnamed")
        assert_allowed(
            resp,
            ok=(201,),
            hint=f" — is '{self.OWNED_SCOPE_UNNAMED}' registered to {USER_USERNAME}? "
            "The init script adds it.",
        )

    def test_user_cannot_create_did_in_foreign_scope_sharing_its_prefix(self, user_token):
        assert_denied(create_dataset(user_token, self.FOREIGN_SCOPE_PREFIXED, "prefixleak"))

    def test_user_cannot_create_did_in_foreign_scope(self, user_token):
        assert_denied(create_dataset(user_token, self.FOREIGN_SCOPE, "foreign"))

    def test_admin_can_create_did_in_any_scope(self, admin_token):
        """Privilege short-circuits ownership."""
        assert_allowed(create_dataset(admin_token, self.FOREIGN_SCOPE, "adminforeign"), ok=(201,))


# ── Privilege via add_rse / RSE attributes (phases 4 and 5) ───────────────


class RsePrivilegeContract:
    """CERN_DATADISK passes the Rego naming rule, so a deny on it is a
    privilege decision; CERN_UNKNOWN fails the rule regardless of who asks."""

    VALID_RSE = "CERN_DATADISK"
    BAD_NAME_RSE = "CERN_UNKNOWN"

    def test_admin_allows_add_rse(self, admin_token):
        resp = rucio_rest(f"/rses/{self.VALID_RSE}", admin_token, "POST", {"rse_type": "DISK"})
        # 409: created by a previous run — the policy still allowed the call.
        assert_allowed(resp, ok=(201, 409), hint=AUTH_HINT)

    def test_user_denied_add_rse(self, user_token):
        assert_denied(
            rucio_rest(f"/rses/{self.VALID_RSE}", user_token, "POST", {"rse_type": "DISK"})
        )

    def test_admin_denied_bad_rse_name(self, admin_token):
        """_perm_add_rse needs privilege and a valid name."""
        assert_denied(
            rucio_rest(f"/rses/{self.BAD_NAME_RSE}", admin_token, "POST", {"rse_type": "DISK"})
        )

    def test_admin_allows_del_rse_attribute(self, admin_token):
        """Privileged-only with no domain check. The attribute doesn't exist,
        so the expected outcome is a not-found — asserted specifically, since
        "not AccessDenied" would also pass on CannotAuthenticate."""
        resp = rucio_rest(f"/rses/{self.VALID_RSE}/attr/{unique('nokey')}", admin_token, "DELETE")
        assert deny_reason(resp)[0] in (None, "KeyNotFound", "RSEAttributeNotFound"), (
            f"HTTP {resp.status_code} {deny_reason(resp)}"
        )

    def test_user_denied_del_rse_attribute(self, user_token):
        resp = rucio_rest(f"/rses/{self.VALID_RSE}/attr/{unique('nokey')}", user_token, "DELETE")
        assert deny_reason(resp)[0] == "AccessDenied", (
            f"HTTP {resp.status_code} {deny_reason(resp)}"
        )


# ── Phase 6 ───────────────────────────────────────────────────────────────

# set_local_account_limit is gated purely on _is_privileged via the
# catch-all, and unlike add_rse isn't subject to the RSE-name allowlist, so a
# deny is unambiguously an entitlement decision. Idempotent.
PRIVILEGED_PATH = "/accounts/ddmlab/limits/local/XRD3"
PRIVILEGED_BODY = {"bytes": -1}


def privileged_call(token: str):
    return rucio_rest(PRIVILEGED_PATH, token, "POST", PRIVILEGED_BODY)


class PrivilegedPathContract:
    def test_admin_entitlement_allows_privileged_action(self, admin_token):
        assert_allowed(privileged_call(admin_token), hint=AUTH_HINT)

    def test_user_entitlement_denies_privileged_action(self, user_token):
        assert_denied(privileged_call(user_token))


class BulkScopeOwnershipContract(RucioIdentities):
    """add_dids carries scopes nested in a list. Worth exercising over REST:
    the nested InternalScope objects must survive serialisation into the
    authorisation input, or the request fails closed before the Rego runs."""

    def test_bulk_add_in_owned_scopes(self, user_token):
        ts = unique("bulk")
        resp = rucio_rest(
            "/dids",
            user_token,
            "POST",
            [
                {"scope": self.OWNED_SCOPE, "name": f"{ts}-a", "type": "DATASET"},
                {"scope": self.OWNED_SCOPE_UNNAMED, "name": f"{ts}-b", "type": "DATASET"},
            ],
        )
        assert_allowed(resp, ok=(201, 409))

    def test_bulk_add_denied_when_one_scope_is_foreign(self, user_token):
        ts = unique("bulk")
        resp = rucio_rest(
            "/dids",
            user_token,
            "POST",
            [
                {"scope": self.OWNED_SCOPE, "name": f"{ts}-c", "type": "DATASET"},
                {"scope": self.FOREIGN_SCOPE, "name": f"{ts}-d", "type": "DATASET"},
            ],
        )
        assert_denied(resp)


def add_rule_over_new_dataset(token: str, scope: str, account: str, prefix: str):
    """Create a dataset in `scope`, then a rule over it owned by `account`."""
    name = unique(prefix)
    rucio_rest(f"/dids/{scope}/{name}", token, "POST", {"type": "DATASET"})
    return rucio_rest(
        "/rules/",
        token,
        "POST",
        {
            "dids": [{"scope": scope, "name": name}],
            "copies": 1,
            "rse_expression": "XRD4",
            "account": account,
        },
    )


class RuleSelfServiceContract(RucioIdentities):
    def test_user_can_add_rule_for_own_account(self, user_token):
        resp = add_rule_over_new_dataset(user_token, self.OWNED_SCOPE, USER_USERNAME, "ownrule")
        assert_allowed(resp, ok=(201,))

    def test_user_cannot_add_rule_for_another_account(self, user_token):
        """Rucio answers 500, not 401: POST /rules/ doesn't translate the
        AccessDenied, so ErrorHandlingMethodView reports it as an untranslated
        RucioException. The policy does deny — so the assertion is "no rule
        was created". Tighten to (401, 403) if Rucio fixes the translation."""
        resp = add_rule_over_new_dataset(
            user_token, self.OWNED_SCOPE, self.OTHER_ACCOUNT, "otherrule"
        )
        assert resp.status_code != 201, f"rule was created for another account: {resp.text[:200]}"


class DepPersonaContract:
    """DEP personas (design-008) over real REST: the operator lands on the
    admin tier, the end user on the user tier."""

    def test_dep_operator_privileged_action_allowed(self, dep_operator_token):
        assert_allowed(privileged_call(dep_operator_token), hint=AUTH_HINT)

    def test_dep_end_user_privileged_action_denied(self, dep_end_user_token):
        assert_denied(privileged_call(dep_end_user_token))

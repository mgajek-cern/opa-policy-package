"""
Phase 6 — the OIDC → has_permission() → OPA path with real tokens
(AUTHZ_MODE=direct).

PrivilegedPathContract covers the claims plumbing: an entitlement that maps to
"admin" in the bundle. The ownership contracts gate on kwargs.owned_scopes and
kwargs.account instead, so they exercise the Rego plus the scopes-table lookup.
"""

from helpers import DEP_END_USER_USERNAME, MODEL_DEVELOPER_USERNAME
from rucio_contracts import (
    BulkScopeOwnershipContract,
    DepPersonaContract,
    PrivilegedPathContract,
    RuleSelfServiceContract,
    ScopeOwnershipContract,
    add_rule_over_new_dataset,
    assert_allowed,
    assert_denied,
    create_dataset,
    privileged_call,
)


class TestEntitlementAuthorisation(PrivilegedPathContract):
    pass


class TestScopeOwnership(ScopeOwnershipContract):
    pass


class TestBulkScopeOwnership(BulkScopeOwnershipContract):
    pass


class TestRuleSelfService(RuleSelfServiceContract):
    pass


class TestDepPersonaAuthorisation(DepPersonaContract):
    """Beyond the shared persona checks: self-service for the user-tier personas."""

    def test_dep_end_user_can_create_did_in_own_scope(self, dep_end_user_token):
        resp = create_dataset(dep_end_user_token, DEP_END_USER_USERNAME, "dependuser")
        assert_allowed(resp, ok=(201,))

    def test_model_developer_privileged_action_denied(self, model_developer_token):
        assert_denied(privileged_call(model_developer_token))

    def test_model_developer_can_add_rule_for_own_account(self, model_developer_token):
        resp = add_rule_over_new_dataset(
            model_developer_token,
            MODEL_DEVELOPER_USERNAME,
            MODEL_DEVELOPER_USERNAME,
            "modeldevrule",
        )
        assert_allowed(resp, ok=(201,))

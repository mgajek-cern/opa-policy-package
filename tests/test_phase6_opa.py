"""
Phase 6 — scenario tests against a live OPA server.

Same entitlement model as phase 5, plus the testbed RSE-name allowlist and
the design-007 restructure: one rule per action, so add_dids and
attach_dids_to_dids each check every item in their own list, and replica
actions require file-scope ownership rather than just a privilege tier.

`make test-opa` exports OPA_URL, so the suite runs against the testbed's own
OPA; every fixture that writes to its data bundle restores what was there.
"""

from pathlib import Path

from opa_contracts import (
    VALID_RSE,
    AcrContract,
    AddRuleOwnershipContract,
    ClaimPolicyBundleContract,
    EntitlementPhase,
    PrivilegedRuleActionsContract,
    PrivilegeTierContract,
    RootBootstrapContract,
    RuleOwnershipContract,
    urn,
)
from rucio_opa_v5_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase6" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v5/allow"
CLAIM_POLICY_PATH = "vo/entitlement_policy"

# DEP persona entitlements (design-008), mapped onto the existing admin/user
# tiers. No new Rego branch: these confirm the mapping lands on the expected
# tier.
DEP_OPERATOR = urn("dep-operator")
DEP_END_USER = urn("dep-end-user")
MODEL_DEVELOPER = urn("model-developer")


class Phase6(EntitlementPhase):
    """Names mirror what scripts/init-phase6.sh creates: randomaccount owns a
    scope named after it and one that is not; ddmlab owns a scope whose name
    starts with "randomaccount"."""

    query = staticmethod(query_opa)

    USER_NAME = "randomaccount"
    OTHER_NAME = "ddmlab"
    OWNED_SCOPE = "randomaccount"
    FOREIGN_SCOPE = "ddmlab"
    FOREIGN_PREFIXED = "randomaccountleak"

    @property
    def owned_files(self):
        return [
            {"scope": self.OWNED_SCOPE, "name": "f1"},
            {"scope": self.OWNED_UNNAMED, "name": "f2"},
        ]

    @property
    def both_owned(self):
        return [self.OWNED_SCOPE, self.OWNED_UNNAMED]


# ── Shared scenarios ──────────────────────────────────────────────────────


class TestEntitlementPrivilege(Phase6, PrivilegeTierContract):
    def test_approve_rule_requires_admin_entitlement(self):
        """Reaches _is_privileged through the unknown-action catch-all since
        design-004 removed approve_rule from _rule_actions."""
        assert self.q(self.USER_NAME, "approve_rule", claims=[self.USER]) is False
        assert self.q(self.ADMIN_NAME, "approve_rule", claims=[self.ADMIN]) is True


class TestAcrConstraint(Phase6, AcrContract):
    pass


class TestAddRuleOwnership(Phase6, AddRuleOwnershipContract):
    pass


class TestRuleOwnership(Phase6, RuleOwnershipContract):
    pass


class TestPrivilegedRuleActions(Phase6, PrivilegedRuleActionsContract):
    pass


class TestRootBootstrap(Phase6, RootBootstrapContract):
    def test_root_allowed_add_replicas_without_files(self):
        assert self.root("add_replicas", rse="XRD3") is True


class TestEntitlementPolicyBundle(Phase6, ClaimPolicyBundleContract):
    def test_bundle_user_tier_reaches_add_replicas(self, claim_policy):
        """The bundle's second tier is policy, not documentation — and on top
        of it, phase 6 requires file-scope ownership."""
        claim_policy({self.ADMIN: "admin", self.USER: "user"})
        for claims, expected in (([self.USER], True), ([self.ATLAS_USER], False)):
            assert (
                self.q(
                    self.USER_NAME,
                    "add_replicas",
                    claims=claims,
                    rse=VALID_RSE,
                    files=self.owned_files,
                    owned_scopes=self.both_owned,
                )
                is expected
            )


# ── Scope ownership ───────────────────────────────────────────────────────
#
# kwargs.owned_scopes carries only the scopes of *this* request that the
# issuer owns. These are the cases the old name-prefix check got wrong in
# both directions.


class TestScopeOwnership(Phase6):
    def _add_did(self, scope, owned_scopes=None, issuer=None, claims=None):
        return self.q(
            issuer or self.USER_NAME,
            "add_did",
            claims=claims or [self.USER],
            scope=scope,
            name="file1",
            owned_scopes=owned_scopes,
        )

    def test_owned_scope_allowed(self):
        assert self._add_did(self.OWNED_SCOPE, [self.OWNED_SCOPE]) is True

    def test_owned_scope_not_named_after_account_allowed(self):
        """The under-permissive half: a prefix check would deny this."""
        assert self._add_did(self.OWNED_UNNAMED, [self.OWNED_UNNAMED]) is True

    def test_foreign_scope_with_matching_prefix_denied(self):
        """The over-permissive half: a prefix check would allow this."""
        assert self._add_did(self.FOREIGN_PREFIXED, [self.OWNED_SCOPE]) is False

    def test_unowned_scope_denied(self):
        assert self._add_did(self.FOREIGN_SCOPE, [self.OWNED_SCOPE]) is False

    def test_missing_owned_scopes_denies(self):
        """No owned_scopes key at all — undefined, so no clause matches."""
        assert self._add_did(self.OWNED_SCOPE) is False

    def test_privileged_allowed_without_ownership(self):
        assert (
            self._add_did(self.FOREIGN_SCOPE, [], issuer=self.ADMIN_NAME, claims=[self.ADMIN])
            is True
        )

    def test_detach_follows_the_same_rule(self):
        for scope, expected in ((self.OWNED_SCOPE, True), (self.FOREIGN_SCOPE, False)):
            assert (
                self.q(
                    self.USER_NAME,
                    "detach_dids",
                    claims=[self.USER],
                    scope=scope,
                    name="container",
                    owned_scopes=[self.OWNED_SCOPE],
                )
                is expected
            )


class TestBulkScopeOwnership(Phase6):
    def _add_dids(self, dids, owned_scopes):
        return self.q(
            self.USER_NAME, "add_dids", claims=[self.USER], dids=dids, owned_scopes=owned_scopes
        )

    def _attach(self, scope):
        return self.q(
            self.USER_NAME,
            "attach_dids_to_dids",
            claims=[self.USER],
            attachments=[
                {"scope": scope, "name": "container", "dids": [{"scope": scope, "name": "f1"}]}
            ],
            owned_scopes=[self.OWNED_SCOPE],
        )

    def test_add_dids_all_scopes_owned(self):
        assert self._add_dids(self.owned_files, self.both_owned) is True

    def test_add_dids_one_scope_unowned_denies_the_batch(self):
        dids = [
            {"scope": self.OWNED_SCOPE, "name": "f1"},
            {"scope": self.FOREIGN_SCOPE, "name": "f2"},
        ]
        assert self._add_dids(dids, [self.OWNED_SCOPE]) is False

    def test_add_dids_empty_batch_denies(self):
        assert self._add_dids([], [self.OWNED_SCOPE]) is False

    def test_attach_dids_to_dids_owned_attachment(self):
        assert self._attach(self.OWNED_SCOPE) is True

    def test_attach_dids_to_dids_unowned_attachment(self):
        assert self._attach(self.FOREIGN_SCOPE) is False


# ── Replicas — ownership of every file's scope (design-005) ───────────────


class TestReplicaRegister(Phase6):
    def _register(self, claims, rse=VALID_RSE, **kw):
        return self.q(self.USER_NAME, "add_replicas", claims=claims, rse=rse, **kw)

    def test_admin_allowed_without_files(self):
        assert self.q(self.ADMIN_NAME, "add_replicas", claims=[self.ADMIN], rse=VALID_RSE) is True

    def test_user_allowed_when_every_file_scope_owned(self):
        assert (
            self._register([self.USER], files=self.owned_files, owned_scopes=self.both_owned)
            is True
        )

    def test_user_denied_when_one_file_scope_foreign(self):
        files = [
            {"scope": self.OWNED_SCOPE, "name": "f1"},
            {"scope": self.FOREIGN_SCOPE, "name": "f2"},
        ]
        assert self._register([self.USER], files=files, owned_scopes=[self.OWNED_SCOPE]) is False

    def test_user_denied_without_files(self):
        """No files at all now denies — the change from the original phase 6 model."""
        assert self._register([self.USER]) is False

    def test_user_denied_on_invalid_rse_name_even_when_owner(self):
        assert (
            self._register(
                [self.USER], rse="cern_bad", files=self.owned_files, owned_scopes=self.both_owned
            )
            is False
        )

    def test_no_entitlements_denied(self):
        assert self._register([], files=self.owned_files, owned_scopes=self.both_owned) is False


class TestReplicaDelete(Phase6):
    def test_admin_allowed_without_files(self):
        assert (
            self.q(self.ADMIN_NAME, "delete_replicas", claims=[self.ADMIN], rse=VALID_RSE) is True
        )

    def test_user_allowed_when_every_file_scope_owned(self):
        assert (
            self.q(
                self.USER_NAME,
                "delete_replicas",
                claims=[self.USER],
                rse=VALID_RSE,
                files=self.owned_files,
                owned_scopes=self.both_owned,
            )
            is True
        )

    def test_no_rse_name_check_on_delete(self):
        assert (
            self.q(
                self.USER_NAME,
                "delete_replicas",
                claims=[self.USER],
                rse="cern_bad",
                files=self.owned_files,
                owned_scopes=self.both_owned,
            )
            is True
        )


# ── RSE-name allowlist ────────────────────────────────────────────────────
#
# The testbed RSEs (XRD3, TEAPOT1, ...) don't follow NAME_TYPE, so the bundle
# names them rather than relaxing the convention. Don't assert on the list
# being absent: the testbed bundle sets it.


class TestRseAllowlist(Phase6):
    def _add_rse(self, rse):
        return self.q(self.ADMIN_NAME, "add_rse", claims=[self.ADMIN], rse=rse)

    def test_unlisted_name_still_needs_the_convention(self):
        assert self._add_rse("NOTANRSE") is False

    def test_testbed_rse_allowed_with_allowlist(self, policy_leaf):
        policy_leaf("allowlisted_rse_names", ["XRD3", "XRD4", "TEAPOT1", "TEAPOT2"])
        assert self._add_rse("XRD3") is True

    def test_convention_still_applies_to_other_names(self, policy_leaf):
        policy_leaf("allowlisted_rse_names", ["XRD3"])
        assert self._add_rse(VALID_RSE) is True
        assert self._add_rse("cern_bad") is False


# ── DEP personas (design-008) ─────────────────────────────────────────────


class TestDepOperatorAuthorisation(Phase6):
    """DEP Operator -> admin tier."""

    def test_privileged_action_allowed(self):
        assert self.q("depoperator", "del_rse", claims=[DEP_OPERATOR]) is True

    def test_add_rse_allowed(self):
        assert self.q("depoperator", "add_rse", claims=[DEP_OPERATOR], rse=VALID_RSE) is True

    def test_catch_all_privileged_action_allowed(self):
        assert self.q("depoperator", "approve_rule", claims=[DEP_OPERATOR]) is True


class TestDepEndUserAuthorisation(Phase6):
    """DEP End User -> user tier: privileged actions denied, ownership-gated
    self-service behaves like any other user-tier entitlement."""

    def test_privileged_action_denied(self):
        assert self.q("dependuser", "del_rse", claims=[DEP_END_USER]) is False

    def test_owned_scope_did_allowed(self):
        assert (
            self.q(
                "dependuser",
                "add_did",
                claims=[DEP_END_USER],
                scope=self.OWNED_SCOPE,
                name="file1",
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )

    def test_add_replicas_requires_file_ownership_like_any_user_tier(self):
        assert (
            self.q(
                "dependuser",
                "add_replicas",
                claims=[DEP_END_USER],
                rse=VALID_RSE,
                files=self.owned_files,
                owned_scopes=self.both_owned,
            )
            is True
        )
        assert self.q("dependuser", "add_replicas", claims=[DEP_END_USER], rse=VALID_RSE) is False


class TestModelDeveloperAuthorisation(Phase6):
    """Model Developer -> user tier, the same shape as DEP End User at the
    Rucio authz boundary; the personas diverge outside it (design-008)."""

    def test_privileged_action_denied(self):
        assert self.q("modeldeveloper", "del_rse", claims=[MODEL_DEVELOPER]) is False

    def test_owned_scope_did_allowed(self):
        assert (
            self.q(
                "modeldeveloper",
                "add_did",
                claims=[MODEL_DEVELOPER],
                scope=self.OWNED_SCOPE,
                name="file1",
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )

    def test_rule_self_service_allowed_for_own_account(self):
        assert (
            self.q(
                "modeldeveloper",
                "add_rule",
                claims=[MODEL_DEVELOPER],
                account="modeldeveloper",
                locked=False,
                rse_expression=VALID_RSE,
                dids=[{"scope": self.OWNED_SCOPE, "name": "f1"}],
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )

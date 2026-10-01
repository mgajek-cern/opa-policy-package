"""
Scenario contracts shared by the phase 4, 5 and 6 OPA suites.

A contract is a mixin of test methods written against `self.q(...)` and the
per-phase names on OpaPhase. A test module defines its phase once and
combines it with the contracts that hold for it:

    class Phase5(EntitlementPhase):
        query = staticmethod(query_opa)
        ...

    class TestRuleOwnership(Phase5, RuleOwnershipContract):
        pass

Nothing here is collected on its own: pytest only collects Test* classes,
and this module defines none.
"""

from __future__ import annotations

from typing import Any

from helpers import MFA, RULE_ID

VALID_RSE = "CERN_DATADISK"
BAD_RSE = "cern_bad"


class OpaPhase:
    """Per-phase settings the contracts read."""

    # Token claim permission.py forwards: "groups" (phase 4) or "entitlements".
    CLAIM = "entitlements"
    # The phase package's query_opa, as staticmethod(query_opa).
    query: Any = None

    # Claim values the phase's bundle maps.
    ADMIN = ""
    USER = ""
    ATLAS_PROD = ""
    ATLAS_USER = ""
    # Deliberately not a realm value: something no bundle would carry.
    UNMAPPED = ""
    CUSTOM_ADMIN = ""

    # Accounts and scopes. The scopes matter only as strings compared against
    # kwargs.owned_scopes, which permission.py resolves from the scopes table.
    ADMIN_NAME = "adminuser"
    USER_NAME = ""
    OTHER_NAME = ""
    OWNED_SCOPE = ""
    OWNED_UNNAMED = "projectdata"
    FOREIGN_SCOPE = ""
    FOREIGN_PREFIXED = ""

    def q(
        self,
        issuer: str,
        action: str,
        *,
        claims=None,
        acr=None,
        owned_scopes=None,
        rule_owner=None,
        rule_scope=None,
        **kw,
    ) -> bool:
        """Query with a token shaped the way permission.py forwards one.

        The claim list is always present, so a Rego clause iterating it is
        safe; `acr` only when the token carries it. `owned_scopes`,
        `rule_owner` and `rule_scope` ride in kwargs rather than the token —
        they are resolved against the scopes and rules tables, not read off a
        claim. Omitting rule_owner/rule_scope models a rule permission.py
        could not resolve, and the deny that follows is the fail-closed path.
        """
        token: dict = {self.CLAIM: claims or []}
        if acr is not None:
            token["acr"] = acr
        for key, value in (
            ("owned_scopes", owned_scopes),
            ("rule_owner", rule_owner),
            ("rule_scope", rule_scope),
        ):
            if value is not None:
                kw[key] = value
        return self.query({"issuer": issuer, "action": action, "token": token, "kwargs": kw})

    def root(self, action: str, **kw) -> bool:
        """root authenticates by userpass, so it carries no claims."""
        return self.query(
            {"issuer": "root", "action": action, "token": {self.CLAIM: []}, "kwargs": kw}
        )


def urn(group: str) -> str:
    return f"urn:example:aai.example.org:group:{group}:role=member"


class EntitlementPhase(OpaPhase):
    """URN entitlements, shared by phases 5 and 6."""

    CLAIM = "entitlements"
    ADMIN = urn("rucio-admins")
    USER = urn("rucio-users")
    ATLAS_PROD = urn("atlas-production")
    ATLAS_USER = urn("atlas-users")
    UNMAPPED = urn("unknown")
    CUSTOM_ADMIN = urn("cms-production")


# ── Privilege from claims ─────────────────────────────────────────────────


class PrivilegeTierContract:
    def test_admin_claim_grants_del_rse(self):
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN]) is True

    def test_user_claim_denies_del_rse(self):
        assert self.q(self.USER_NAME, "del_rse", claims=[self.USER]) is False

    def test_no_claims_denies_privileged_action(self):
        assert self.q(self.USER_NAME, "del_rse", claims=[]) is False

    def test_atlas_production_is_admin(self):
        assert self.q("prod", "add_rse", claims=[self.ATLAS_PROD], rse=VALID_RSE) is True

    def test_atlas_users_is_not_admin(self):
        assert self.q(self.USER_NAME, "add_rse", claims=[self.ATLAS_USER], rse=VALID_RSE) is False

    def test_any_admin_claim_grants_privilege(self):
        """The admin realm user's real token carries both of these."""
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ATLAS_PROD, self.ADMIN]) is True

    def test_user_claims_together_grant_nothing(self):
        """The ordinary realm user's real token carries both, neither admin."""
        assert self.q(self.USER_NAME, "del_rse", claims=[self.USER, self.ATLAS_USER]) is False

    def test_naming_rule_still_blocks_admin(self):
        """Domain checks apply regardless of privilege."""
        assert (
            self.q(
                self.ADMIN_NAME,
                "add_rule",
                claims=[self.ADMIN],
                account=self.ADMIN_NAME,
                locked=False,
                rse_expression=BAD_RSE,
            )
            is False
        )


# ── Authentication context (acr) ──────────────────────────────────────────
#
# data.vo.policy.required_acr gates the OIDC privilege path only. The realm
# users all carry the same acr, so the deny branch is only reachable with
# synthetic input — which is why this lives in the OPA suites.


class AcrContract:
    def test_acr_ignored_when_not_required(self):
        """Assumes the loaded bundle sets no required_acr, the default.

        Don't PUT null to pin it: null is a defined value in Rego, so
        `not data.vo.policy.required_acr` would fail and every privileged
        action would be denied.
        """
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN], acr=MFA) is True
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN]) is True

    def test_admin_allowed_when_acr_matches(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN], acr=MFA) is True

    def test_admin_denied_when_acr_missing(self, policy_leaf):
        """An admin claim is no longer sufficient on its own."""
        policy_leaf("required_acr", MFA)
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN]) is False

    def test_admin_denied_when_acr_differs(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert (
            self.q(
                self.ADMIN_NAME,
                "del_rse",
                claims=[self.ADMIN],
                acr="urn:mace:incommon:iap:silver",
            )
            is False
        )

    def test_root_bootstrap_unaffected_by_acr(self, policy_leaf):
        """root has no token and therefore no acr — gating it would strand the stack."""
        policy_leaf("required_acr", MFA)
        assert self.root("del_rse") is True

    def test_rule_self_service_unaffected_by_acr(self, policy_leaf):
        """Ownership clauses don't route through _is_privileged."""
        policy_leaf("required_acr", MFA)
        assert (
            self.q(
                self.USER_NAME,
                "del_rule",
                claims=[self.USER],
                rule_id=RULE_ID,
                rule_owner=self.USER_NAME,
            )
            is True
        )

    def test_scope_ownership_unaffected_by_acr(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert (
            self.q(
                self.USER_NAME,
                "add_did",
                claims=[self.USER],
                scope=self.OWNED_SCOPE,
                name="file1",
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )


# ── add_rule — rule ownership AND data ownership (design-004) ─────────────
#
# kwargs.account is the account the new rule will belong to; kwargs.dids
# names the data it replicates. Owning the rule you create says nothing about
# owning what it pulls, so both are checked.


class AddRuleOwnershipContract:
    def _add_rule(self, issuer, claims, *, account, dids, owned_scopes, locked=False):
        return self.q(
            issuer,
            "add_rule",
            claims=claims,
            account=account,
            locked=locked,
            rse_expression=VALID_RSE,
            dids=dids,
            owned_scopes=owned_scopes,
        )

    def _user_rule(self, dids, owned_scopes, **kw):
        kw.setdefault("account", self.USER_NAME)
        return self._add_rule(
            self.USER_NAME, [self.USER], dids=dids, owned_scopes=owned_scopes, **kw
        )

    def test_user_can_add_own_rule_over_own_data(self):
        dids = [{"scope": self.OWNED_SCOPE, "name": "f1"}]
        assert self._user_rule(dids, [self.OWNED_SCOPE]) is True

    def test_user_can_add_rule_over_owned_scope_not_named_after_account(self):
        dids = [{"scope": self.OWNED_UNNAMED, "name": "f1"}]
        assert self._user_rule(dids, [self.OWNED_UNNAMED]) is True

    def test_user_denied_rule_over_foreign_data(self):
        """The tenancy case: the issuer's own rule, but another account's data."""
        dids = [{"scope": self.FOREIGN_SCOPE, "name": "f1"}]
        assert self._user_rule(dids, []) is False

    def test_user_denied_rule_over_prefix_matching_foreign_scope(self):
        dids = [{"scope": self.FOREIGN_PREFIXED, "name": "f1"}]
        assert self._user_rule(dids, [self.OWNED_SCOPE]) is False

    def test_user_denied_when_one_did_is_foreign(self):
        dids = [
            {"scope": self.OWNED_SCOPE, "name": "f1"},
            {"scope": self.FOREIGN_SCOPE, "name": "f2"},
        ]
        assert self._user_rule(dids, [self.OWNED_SCOPE]) is False

    def test_empty_did_list_denied(self):
        """`every` over an empty collection is vacuously true — count() is what
        stops a no-DID request from being allowed."""
        assert self._user_rule([], [self.OWNED_SCOPE]) is False

    def test_user_denied_locked_rule(self):
        dids = [{"scope": self.OWNED_SCOPE, "name": "f1"}]
        assert self._user_rule(dids, [self.OWNED_SCOPE], locked=True) is False

    def test_user_denied_rule_for_other_account(self):
        dids = [{"scope": self.OWNED_SCOPE, "name": "f1"}]
        assert self._user_rule(dids, [self.OWNED_SCOPE], account=self.OTHER_NAME) is False

    def test_admin_allowed_over_foreign_data(self):
        """Privilege short-circuits ownership, as it does for DIDs."""
        assert (
            self._add_rule(
                self.ADMIN_NAME,
                [self.ADMIN],
                account=self.ADMIN_NAME,
                dids=[{"scope": self.FOREIGN_SCOPE, "name": "f1"}],
                owned_scopes=[],
            )
            is True
        )


# ── del_rule / update_rule — facts from the rules table (design-004) ──────
#
# kwargs carry only rule_id; rule_owner and rule_scope are fetched by
# permission.py via get_rule(). Their absence models a rule that could not be
# resolved, and must deny.


class RuleOwnershipContract:
    def _update(self, issuer, claims, **kw):
        return self.q(issuer, "update_rule", claims=claims, rule_id=RULE_ID, **kw)

    def test_owner_can_delete_own_rule(self):
        assert (
            self.q(
                self.USER_NAME,
                "del_rule",
                claims=[self.USER],
                rule_id=RULE_ID,
                rule_owner=self.USER_NAME,
            )
            is True
        )

    def test_non_owner_denied_delete(self):
        assert (
            self.q(
                self.USER_NAME,
                "del_rule",
                claims=[self.USER],
                rule_id=RULE_ID,
                rule_owner=self.OTHER_NAME,
            )
            is False
        )

    def test_unresolvable_rule_denied_delete(self):
        """get_rule() raised, so permission.py omitted the keys — fail closed."""
        assert self.q(self.USER_NAME, "del_rule", claims=[self.USER], rule_id=RULE_ID) is False

    def test_admin_can_delete_any_rule(self):
        assert (
            self.q(
                self.ADMIN_NAME,
                "del_rule",
                claims=[self.ADMIN],
                rule_id=RULE_ID,
                rule_owner=self.OTHER_NAME,
            )
            is True
        )

    def test_owner_can_update_own_rule_over_own_data(self):
        assert (
            self._update(
                self.USER_NAME,
                [self.USER],
                options={"lifetime": 3600},
                rule_owner=self.USER_NAME,
                rule_scope=self.OWNED_SCOPE,
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )

    def test_owner_denied_update_when_scope_unowned(self):
        """Owning the rule is not enough — update can change RSE and lifetime."""
        assert (
            self._update(
                self.USER_NAME,
                [self.USER],
                options={"lifetime": 3600},
                rule_owner=self.USER_NAME,
                rule_scope=self.FOREIGN_SCOPE,
                owned_scopes=[self.OWNED_SCOPE],
            )
            is False
        )

    def test_update_without_options_allowed_for_owner(self):
        """`options` absent entirely must not read as a reassignment."""
        assert (
            self._update(
                self.USER_NAME,
                [self.USER],
                rule_owner=self.USER_NAME,
                rule_scope=self.OWNED_SCOPE,
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )

    def test_reassignment_denied_for_owner(self):
        """Handing a rule to another account is a transfer, not self-service."""
        assert (
            self._update(
                self.USER_NAME,
                [self.USER],
                options={"account": self.OTHER_NAME},
                rule_owner=self.USER_NAME,
                rule_scope=self.OWNED_SCOPE,
                owned_scopes=[self.OWNED_SCOPE],
            )
            is False
        )

    def test_reassignment_to_self_still_denied(self):
        """The predicate keys on the field being present, not on its value."""
        assert (
            self._update(
                self.USER_NAME,
                [self.USER],
                options={"account": self.USER_NAME},
                rule_owner=self.USER_NAME,
                rule_scope=self.OWNED_SCOPE,
                owned_scopes=[self.OWNED_SCOPE],
            )
            is False
        )

    def test_reassignment_allowed_for_admin(self):
        assert (
            self._update(
                self.ADMIN_NAME,
                [self.ADMIN],
                options={"account": self.OTHER_NAME},
                rule_owner=self.USER_NAME,
                rule_scope=self.OWNED_SCOPE,
                owned_scopes=[],
            )
            is True
        )

    def test_unresolvable_rule_denied_update(self):
        assert (
            self._update(
                self.USER_NAME,
                [self.USER],
                options={"lifetime": 3600},
                owned_scopes=[self.OWNED_SCOPE],
            )
            is False
        )


class PrivilegedRuleActionsContract:
    """Rule actions design-004 leaves privileged-only."""

    def test_reduce_rule_privileged_only(self):
        assert self.q(self.USER_NAME, "reduce_rule", claims=[self.USER], rule_id=RULE_ID) is False
        assert self.q(self.ADMIN_NAME, "reduce_rule", claims=[self.ADMIN], rule_id=RULE_ID) is True

    def test_move_rule_privileged_only(self):
        assert self.q(self.USER_NAME, "move_rule", claims=[self.USER], rule_id=RULE_ID) is False
        assert self.q(self.ADMIN_NAME, "move_rule", claims=[self.ADMIN], rule_id=RULE_ID) is True


# ── Root bootstrap (no OIDC token) ────────────────────────────────────────


class RootBootstrapContract:
    def test_root_allowed_del_rse(self):
        assert self.root("del_rse") is True

    def test_root_allowed_add_rse_valid_name(self):
        assert self.root("add_rse", rse=VALID_RSE) is True

    def test_root_allowed_unknown_action(self):
        assert self.root("some_unknown_action") is True

    def test_root_allowed_did_action_without_ownership(self):
        """The transfer suite creates datasets as root."""
        assert self.root("add_did", scope=self.FOREIGN_SCOPE, name="dataset1") is True

    def test_root_allowed_rule_action_without_facts(self):
        """The transfer suite creates and deletes rules as root."""
        assert self.root("del_rule", rule_id=RULE_ID) is True

    def test_root_blocked_by_naming_rule(self):
        assert self.root("add_rule", account="root", locked=False, rse_expression=BAD_RSE) is False

    def test_non_root_without_claims_denied_privileged(self):
        assert self.q(self.USER_NAME, "del_rse", claims=[]) is False


# ── Claim → privilege bundle override (runtime) ───────────────────────────
#
# Each test sets the whole mapping it needs and claim_policy restores the
# previous one, so nothing depends on declaration order or leaves the
# testbed's bundle rewritten.


class ClaimPolicyBundleContract:
    def test_custom_claim_granted_after_bundle_push(self, claim_policy):
        claim_policy({self.CUSTOM_ADMIN: "admin", self.USER: "user"})
        assert self.q("cmsuser", "del_rse", claims=[self.CUSTOM_ADMIN]) is True

    def test_removed_claim_loses_privilege(self, claim_policy):
        claim_policy({self.ATLAS_PROD: "admin"})
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN]) is False
        assert self.q("prod", "del_rse", claims=[self.ATLAS_PROD]) is True

    def test_bundle_restored_after_override(self):
        """claim_policy put the testbed's own mapping back."""
        assert self.q(self.ADMIN_NAME, "del_rse", claims=[self.ADMIN]) is True


# ── Phases 4 and 5 only ───────────────────────────────────────────────────
#
# Phase 6 restructured DID and replica rules (design-007: one rule per
# action, replicas gated on file-scope ownership), so it carries its own
# versions of these in test_phase6_opa.py.


class UserActionsContract:
    def test_user_can_add_did_to_own_scope(self):
        assert (
            self.q(
                self.USER_NAME,
                "add_did",
                claims=[self.USER],
                scope=self.OWNED_SCOPE,
                name="file1",
                owned_scopes=[self.OWNED_SCOPE],
            )
            is True
        )

    def test_user_denied_other_scope(self):
        assert (
            self.q(
                self.USER_NAME,
                "add_did",
                claims=[self.USER],
                scope=self.FOREIGN_SCOPE,
                name="file1",
                owned_scopes=[self.OWNED_SCOPE],
            )
            is False
        )

    def test_add_dids_requires_every_scope_owned(self):
        owned = [
            {"scope": self.OWNED_SCOPE, "name": "f1"},
            {"scope": self.OWNED_UNNAMED, "name": "f2"},
        ]
        mixed = [
            {"scope": self.OWNED_SCOPE, "name": "f1"},
            {"scope": self.FOREIGN_SCOPE, "name": "f2"},
        ]
        assert (
            self.q(
                self.USER_NAME,
                "add_dids",
                claims=[self.USER],
                dids=owned,
                owned_scopes=[self.OWNED_SCOPE, self.OWNED_UNNAMED],
            )
            is True
        )
        assert (
            self.q(
                self.USER_NAME,
                "add_dids",
                claims=[self.USER],
                dids=mixed,
                owned_scopes=[self.OWNED_SCOPE],
            )
            is False
        )

    def test_del_protocol_without_scheme_allowed_for_admin(self):
        """del_protocol carries no scheme; the no-scheme clause covers it."""
        assert self.q(self.ADMIN_NAME, "del_protocol", claims=[self.ADMIN]) is True
        assert self.q(self.USER_NAME, "del_protocol", claims=[self.USER]) is False


class UserTierReplicaContract:
    """add_replicas without file scopes: the one rule that tells a claim
    mapped to "user" apart from one mapped to nothing."""

    def test_admin_allowed(self):
        assert self.q(self.ADMIN_NAME, "add_replicas", claims=[self.ADMIN], rse=VALID_RSE) is True

    def test_user_tier_allowed_on_valid_rse_name(self):
        assert self.q(self.USER_NAME, "add_replicas", claims=[self.USER], rse=VALID_RSE) is True

    def test_user_tier_denied_on_invalid_rse_name(self):
        """The naming convention still applies — "user" is not a bypass."""
        assert self.q(self.USER_NAME, "add_replicas", claims=[self.USER], rse=BAD_RSE) is False

    def test_no_claims_denied(self):
        assert self.q("nobody", "add_replicas", claims=[], rse=VALID_RSE) is False

    def test_unmapped_claim_denied(self):
        assert self.q("nobody", "add_replicas", claims=[self.UNMAPPED], rse=VALID_RSE) is False

    def test_bundle_user_tier_reaches_add_replicas(self, claim_policy):
        """The bundle's "user" mapping is policy, not documentation."""
        claim_policy({self.ADMIN: "admin", self.USER: "user"})
        assert self.q(self.USER_NAME, "add_replicas", claims=[self.USER], rse=VALID_RSE) is True
        assert (
            self.q(self.USER_NAME, "add_replicas", claims=[self.UNMAPPED], rse=VALID_RSE) is False
        )

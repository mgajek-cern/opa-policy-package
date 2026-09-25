"""
Phase 6 — e2e scenario tests against a live OPA server.

Same entitlement model as Phase 5, plus the testbed RSE-name allowlist and
DID ownership resolved from `kwargs.owned_scopes` rather than a name
prefix. The Rego was later restructured (see design-007) to one rule per
action instead of shared rules across an action family — e.g. `add_dids`
and `attach_dids_to_dids` each check every item in their own list, rather
than one shared `_perm_did_action` rule; and replica actions now require
file-scope ownership, not just privilege level.

The OPA this runs against may be the testbed's own — `make test-opa` passes
OPA_URL and build_opa_server_fixture reuses it rather than spawning one — so
every test that writes to the data bundle restores what was there. A test
that deletes a leaf instead would break the stack for the Rucio suite.
"""

from pathlib import Path

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v5_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase6" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v5/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")

ADMIN = "urn:example:aai.example.org:group:rucio-admins:role=member"
ATLAS_PROD = "urn:example:aai.example.org:group:atlas-production:role=member"
USER = "urn:example:aai.example.org:group:rucio-users:role=member"
ATLAS_USER = "urn:example:aai.example.org:group:atlas-users:role=member"

# DEP persona entitlements (design-008) — dedicated URNs mapped onto the
# existing admin/user tiers. No new Rego branch: these tests exist to
# confirm the mapping lands on the expected tier, not to exercise new
# permission logic.

DEP_OPERATOR = "urn:example:aai.example.org:group:dep-operator:role=member"
DEP_END_USER = "urn:example:aai.example.org:group:dep-end-user:role=member"
MODEL_DEVELOPER = "urn:example:aai.example.org:group:model-developer:role=member"

MFA = "https://refeds.org/profile/mfa"

# Mirrors what scripts/init-phase6.sh creates: randomaccount owns a scope
# named after it and one that is not; ddmlab owns a scope whose name starts
# with "randomaccount".
OWNED = "randomaccount"
OWNED_UNNAMED = "projectdata"
FOREIGN_PREFIXED = "randomaccountleak"

RULE_ID = "1f0e3dad99908345f7439f8ffabdffc4"

OWNED_FILES = [{"scope": OWNED, "name": "f1"}, {"scope": OWNED_UNNAMED, "name": "f2"}]
BOTH_OWNED = [OWNED, OWNED_UNNAMED]


@pytest.fixture(autouse=True)
def _point_client(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", OPA_POLICY_PATH)


def _q(
    issuer: str,
    action: str,
    *,
    entitlements=None,
    acr=None,
    owned_scopes=None,
    rule_owner=None,
    rule_scope=None,
    **kw,
) -> bool:
    """Query with a token shaped the way permission.py forwards one here.

    `owned_scopes`, `rule_owner` and `rule_scope` ride in kwargs rather than
    the token: they are resolved in permission.py against the `scopes` and
    `rules` tables, not read off a claim. Omitting rule_owner/rule_scope
    models a rule permission.py could not resolve — the deny that follows is
    what the fail-closed path is supposed to produce.
    """
    token = {"entitlements": entitlements or []}
    if acr is not None:
        token["acr"] = acr

    kwargs = dict(kw)
    for key, value in (
        ("owned_scopes", owned_scopes),
        ("rule_owner", rule_owner),
        ("rule_scope", rule_scope),
    ):
        if value is not None:
            kwargs[key] = value

    return query_opa(
        {
            "issuer": issuer,
            "action": action,
            "token": token,
            "kwargs": kwargs,
        }
    )


def _root(action: str, **kw) -> bool:
    return query_opa(
        {
            "issuer": "root",
            "action": action,
            "token": {"entitlements": []},
            "kwargs": kw,
        }
    )


# Entitlement-based privilege


class TestEntitlementPrivilege:
    def test_admin_entitlement_grants_del_rse(self):
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True

    def test_user_entitlement_denies_del_rse(self):
        assert _q("randomaccount", "del_rse", entitlements=[USER]) is False

    def test_no_entitlements_denies_privileged_action(self):
        assert _q("randomaccount", "del_rse", entitlements=[]) is False

    def test_atlas_production_is_admin(self):
        assert _q("prod", "add_rse", entitlements=[ATLAS_PROD], rse="CERN_DATADISK") is True

    def test_approve_rule_requires_admin_entitlement(self):
        """Reaches _is_privileged through the unknown-action catch-all since
        design-004 removed approve_rule from _rule_actions. Outcome unchanged;
        the route is not."""
        assert _q("randomaccount", "approve_rule", entitlements=[USER]) is False
        assert _q("adminuser", "approve_rule", entitlements=[ADMIN]) is True


# Scope ownership
#
# kwargs.owned_scopes is resolved in permission.py against the scopes table
# and carries only the scopes of *this* request that the issuer owns. The
# Rego does the comparison; these cases are the ones the old name-prefix
# check got wrong in both directions.


class TestScopeOwnership:
    def test_owned_scope_allowed(self):
        assert (
            _q(
                "randomaccount",
                "add_did",
                entitlements=[USER],
                scope=OWNED,
                name="file1",
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_owned_scope_not_named_after_account_allowed(self):
        """The under-permissive half: a prefix check would deny this."""
        assert (
            _q(
                "randomaccount",
                "add_did",
                entitlements=[USER],
                scope=OWNED_UNNAMED,
                name="file1",
                owned_scopes=[OWNED_UNNAMED],
            )
            is True
        )

    def test_foreign_scope_with_matching_prefix_denied(self):
        """The over-permissive half: a prefix check would allow this."""
        assert (
            _q(
                "randomaccount",
                "add_did",
                entitlements=[USER],
                scope=FOREIGN_PREFIXED,
                name="file1",
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_unowned_scope_denied(self):
        assert (
            _q(
                "randomaccount",
                "add_did",
                entitlements=[USER],
                scope="ddmlab",
                name="file1",
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_missing_owned_scopes_denies(self):
        """No owned_scopes key at all — undefined, so no clause matches."""
        assert (
            _q("randomaccount", "add_did", entitlements=[USER], scope=OWNED, name="file1") is False
        )

    def test_privileged_allowed_without_ownership(self):
        assert (
            _q(
                "adminuser",
                "add_did",
                entitlements=[ADMIN],
                scope="ddmlab",
                name="file1",
                owned_scopes=[],
            )
            is True
        )

    def test_detach_follows_the_same_rule(self):
        assert (
            _q(
                "randomaccount",
                "detach_dids",
                entitlements=[USER],
                scope=OWNED,
                name="container",
                owned_scopes=[OWNED],
            )
            is True
        )
        assert (
            _q(
                "randomaccount",
                "detach_dids",
                entitlements=[USER],
                scope="ddmlab",
                name="container",
                owned_scopes=[OWNED],
            )
            is False
        )


class TestBulkScopeOwnership:
    def test_add_dids_all_scopes_owned(self):
        assert (
            _q(
                "randomaccount",
                "add_dids",
                entitlements=[USER],
                dids=[
                    {"scope": OWNED, "name": "f1"},
                    {"scope": OWNED_UNNAMED, "name": "f2"},
                ],
                owned_scopes=[OWNED, OWNED_UNNAMED],
            )
            is True
        )

    def test_add_dids_one_scope_unowned_denies_the_batch(self):
        assert (
            _q(
                "randomaccount",
                "add_dids",
                entitlements=[USER],
                dids=[
                    {"scope": OWNED, "name": "f1"},
                    {"scope": "ddmlab", "name": "f2"},
                ],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_add_dids_empty_batch_denies(self):
        assert (
            _q("randomaccount", "add_dids", entitlements=[USER], dids=[], owned_scopes=[OWNED])
            is False
        )

    def test_attach_dids_to_dids_owned_attachment(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids_to_dids",
                entitlements=[USER],
                attachments=[
                    {
                        "scope": OWNED,
                        "name": "container",
                        "dids": [{"scope": OWNED, "name": "f1"}],
                    }
                ],
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_attach_dids_to_dids_unowned_attachment(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids_to_dids",
                entitlements=[USER],
                attachments=[
                    {
                        "scope": "ddmlab",
                        "name": "container",
                        "dids": [{"scope": "ddmlab", "name": "f1"}],
                    }
                ],
                owned_scopes=[OWNED],
            )
            is False
        )


# Authentication context (acr)


class TestAcrConstraint:
    def test_acr_ignored_when_not_required(self):
        """Assumes the loaded bundle sets no required_acr, which is the default.

        Don't PUT null to pin it: in Rego null is a defined value, so
        `not data.vo.policy.required_acr` would fail and every privileged
        action would be denied.
        """
        assert _q("adminuser", "del_rse", entitlements=[ADMIN], acr=MFA) is True
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True

    def test_admin_allowed_when_acr_matches(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", entitlements=[ADMIN], acr=MFA) is True

    def test_admin_denied_when_acr_missing(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False

    def test_root_bootstrap_unaffected_by_acr(self, policy_leaf):
        """root has no token and therefore no acr — the transfer suite runs as root."""
        policy_leaf("required_acr", MFA)
        assert _root("del_rse") is True

    def test_ownership_unaffected_by_acr(self, policy_leaf):
        """Ownership clauses don't route through _is_privileged."""
        policy_leaf("required_acr", MFA)
        assert (
            _q(
                "randomaccount",
                "add_did",
                entitlements=[USER],
                scope=OWNED,
                name="file1",
                owned_scopes=[OWNED],
            )
            is True
        )


# add_rule — rule ownership AND data ownership (design-004)
#
# kwargs.account is the account the new rule will belong to; kwargs.dids
# names the data it replicates. Both are checked: owning the rule you create
# says nothing about owning what it pulls.


class TestAddRuleOwnership:
    def test_user_can_add_own_rule_over_own_data(self):
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": OWNED, "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_user_can_add_rule_over_owned_scope_not_named_after_account(self):
        """The design-003 under-permissive case, now reachable through rules."""
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": OWNED_UNNAMED, "name": "f1"}],
                owned_scopes=[OWNED_UNNAMED],
            )
            is True
        )

    def test_user_denied_rule_over_foreign_data(self):
        """The tenancy case: the issuer's own rule, but ddmlab's datasets."""
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": "ddmlab", "name": "f1"}],
                owned_scopes=[],
            )
            is False
        )

    def test_user_denied_rule_over_prefix_matching_foreign_scope(self):
        """The over-permissive half, through the rule path."""
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": FOREIGN_PREFIXED, "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_user_denied_when_one_did_is_foreign(self):
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[
                    {"scope": OWNED, "name": "f1"},
                    {"scope": "ddmlab", "name": "f2"},
                ],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_empty_did_list_denied(self):
        """`every` over an empty collection is vacuously true — count() is what
        stops a no-DID request from being allowed."""
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_user_denied_rule_for_other_account(self):
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="ddmlab",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": OWNED, "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_admin_allowed_over_foreign_data(self):
        """Privilege short-circuits ownership, as it does for DIDs."""
        assert (
            _q(
                "adminuser",
                "add_rule",
                entitlements=[ADMIN],
                account="adminuser",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": "ddmlab", "name": "f1"}],
                owned_scopes=[],
            )
            is True
        )


# del_rule / update_rule — facts resolved from the rules table (design-004)
#
# kwargs carry only rule_id; rule_owner and rule_scope are fetched by
# permission.py via get_rule(). Their absence models a rule that could not be
# resolved, and must deny.


class TestRuleOwnership:
    def test_owner_can_delete_own_rule(self):
        assert (
            _q(
                "randomaccount",
                "del_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                rule_owner="randomaccount",
            )
            is True
        )

    def test_non_owner_denied_delete(self):
        assert (
            _q(
                "randomaccount",
                "del_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                rule_owner="ddmlab",
            )
            is False
        )

    def test_unresolvable_rule_denied_delete(self):
        """get_rule() raised, so permission.py omitted the keys — fail closed."""
        assert _q("randomaccount", "del_rule", entitlements=[USER], rule_id=RULE_ID) is False

    def test_admin_can_delete_any_rule(self):
        assert (
            _q(
                "adminuser",
                "del_rule",
                entitlements=[ADMIN],
                rule_id=RULE_ID,
                rule_owner="ddmlab",
            )
            is True
        )

    def test_owner_can_update_own_rule_over_own_data(self):
        assert (
            _q(
                "randomaccount",
                "update_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                options={"lifetime": 3600},
                rule_owner="randomaccount",
                rule_scope=OWNED,
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_owner_denied_update_when_scope_unowned(self):
        """Owning the rule is not enough — update can change RSE and lifetime."""
        assert (
            _q(
                "randomaccount",
                "update_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                options={"lifetime": 3600},
                rule_owner="randomaccount",
                rule_scope="ddmlab",
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_update_without_options_allowed_for_owner(self):
        """`options` absent entirely must not read as a reassignment."""
        assert (
            _q(
                "randomaccount",
                "update_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                rule_owner="randomaccount",
                rule_scope=OWNED,
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_reassignment_denied_for_owner(self):
        """Handing a rule to another account is a transfer, not self-service."""
        assert (
            _q(
                "randomaccount",
                "update_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                options={"account": "ddmlab"},
                rule_owner="randomaccount",
                rule_scope=OWNED,
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_reassignment_to_self_still_denied(self):
        """Naming the current owner is a no-op, but the predicate keys on the
        field being present rather than on its value — deliberately."""
        assert (
            _q(
                "randomaccount",
                "update_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                options={"account": "randomaccount"},
                rule_owner="randomaccount",
                rule_scope=OWNED,
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_reassignment_allowed_for_admin(self):
        assert (
            _q(
                "adminuser",
                "update_rule",
                entitlements=[ADMIN],
                rule_id=RULE_ID,
                options={"account": "ddmlab"},
                rule_owner="randomaccount",
                rule_scope=OWNED,
                owned_scopes=[],
            )
            is True
        )

    def test_unresolvable_rule_denied_update(self):
        assert (
            _q(
                "randomaccount",
                "update_rule",
                entitlements=[USER],
                rule_id=RULE_ID,
                options={"lifetime": 3600},
                owned_scopes=[OWNED],
            )
            is False
        )


# Rule actions left privileged by design-004


class TestPrivilegedRuleActions:
    def test_reduce_rule_privileged_only(self):
        assert _q("randomaccount", "reduce_rule", entitlements=[USER], rule_id=RULE_ID) is False
        assert _q("adminuser", "reduce_rule", entitlements=[ADMIN], rule_id=RULE_ID) is True

    def test_move_rule_privileged_only(self):
        assert _q("randomaccount", "move_rule", entitlements=[USER], rule_id=RULE_ID) is False
        assert _q("adminuser", "move_rule", entitlements=[ADMIN], rule_id=RULE_ID) is True


# add_replicas / delete_replicas — ownership of every file's scope, plus
# privilege level (design-005, "Replica ownership"). Changed from the
# original phase 6 model, which had no scope signal in kwargs at all —
# the merged Rego now requires `files` and denies any non-privileged
# request that doesn't supply it, or that names a scope the issuer
# doesn't own.


class TestReplicaRegister:
    def test_admin_allowed_without_files(self):
        assert _q("adminuser", "add_replicas", entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_root_allowed_without_files(self):
        assert _root("add_replicas", rse="XRD3") is True

    def test_user_allowed_when_every_file_scope_owned(self):
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is True
        )

    def test_user_denied_when_one_file_scope_foreign(self):
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=[{"scope": OWNED, "name": "f1"}, {"scope": "ddmlab", "name": "f2"}],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_user_denied_without_files(self):
        """The regression case this class replaces: no files at all now denies."""
        assert (
            _q("randomaccount", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is False
        )

    def test_user_denied_on_invalid_rse_name_even_when_owner(self):
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="cern_bad",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is False
        )

    def test_no_entitlements_denied(self):
        assert (
            _q(
                "carol",
                "add_replicas",
                entitlements=[],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is False
        )


class TestReplicaDelete:
    def test_admin_allowed_without_files(self):
        assert _q("adminuser", "delete_replicas", entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_user_allowed_when_every_file_scope_owned(self):
        assert (
            _q(
                "randomaccount",
                "delete_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is True
        )

    def test_no_rse_name_check_on_delete(self):
        assert (
            _q(
                "randomaccount",
                "delete_replicas",
                entitlements=[USER],
                rse="cern_bad",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is True
        )


# Root bootstrap (no OIDC token)


class TestRootBootstrap:
    def test_root_allowed_del_rse(self):
        assert _root("del_rse") is True

    def test_root_allowed_unknown_action(self):
        assert _root("some_unknown_action") is True

    def test_root_allowed_did_action_without_ownership(self):
        """The transfer suite creates datasets in ddmlab as root."""
        assert _root("add_did", scope="ddmlab", name="dataset1") is True

    def test_root_allowed_rule_action_without_facts(self):
        """The transfer suite creates and deletes rules as root."""
        assert _root("del_rule", rule_id=RULE_ID) is True


# RSE-name allowlist — the Phase 6 addition
#
# The testbed RSEs (XRD3, TEAPOT1, ...) don't follow the NAME_TYPE
# convention, so the bundle names them explicitly rather than relaxing the
# convention for everyone. Don't assert on the allowlist being absent: the
# testbed bundle sets it, and these tests may be pointed at that OPA.


class TestRseAllowlist:
    def test_unlisted_name_still_needs_the_convention(self):
        assert _q("adminuser", "add_rse", entitlements=[ADMIN], rse="NOTANRSE") is False

    def test_testbed_rse_allowed_with_allowlist(self, policy_leaf):
        policy_leaf("allowlisted_rse_names", ["XRD3", "XRD4", "TEAPOT1", "TEAPOT2"])
        assert _q("adminuser", "add_rse", entitlements=[ADMIN], rse="XRD3") is True

    def test_convention_still_applies_to_other_names(self, policy_leaf):
        policy_leaf("allowlisted_rse_names", ["XRD3"])
        assert _q("adminuser", "add_rse", entitlements=[ADMIN], rse="CERN_DATADISK") is True
        assert _q("adminuser", "add_rse", entitlements=[ADMIN], rse="cern_bad") is False


# Entitlement policy bundle override (runtime)
#
# Each test sets the whole mapping it needs and the fixture restores the
# previous one, so these no longer depend on declaration order or leave the
# testbed's bundle rewritten.


class TestEntitlementPolicyBundle:
    def test_custom_entitlement_granted_after_bundle_push(self, entitlement_policy):
        cms_prod = "urn:example:aai.example.org:group:cms-production:role=member"
        entitlement_policy({cms_prod: "admin", USER: "user"})
        assert _q("cmsuser", "del_rse", entitlements=[cms_prod]) is True

    def test_bundle_user_level_reaches_add_replicas(self, entitlement_policy):
        """The bundle's second tier is policy, not documentation. Also now
        requires file-scope ownership, not just the entitlement level."""
        entitlement_policy({ADMIN: "admin", USER: "user"})
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is True
        )
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[ATLAS_USER],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is False
        )

    def test_removed_entitlement_loses_privilege(self, entitlement_policy):
        entitlement_policy({ATLAS_PROD: "admin"})
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False
        assert _q("prod", "del_rse", entitlements=[ATLAS_PROD]) is True

    def test_bundle_restored_after_override(self):
        """The fixture put the testbed's own mapping back."""
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True


class TestDepOperatorAuthorisation:
    """DEP Operator -> admin tier. Same path as ADMIN/ATLAS_PROD."""

    def test_privileged_action_allowed(self):
        assert _q("depoperator", "del_rse", entitlements=[DEP_OPERATOR]) is True

    def test_add_rse_allowed(self):
        assert (
            _q(
                "depoperator",
                "add_rse",
                entitlements=[DEP_OPERATOR],
                rse="CERN_DATADISK",
            )
            is True
        )

    def test_catch_all_privileged_action_allowed(self):
        assert _q("depoperator", "approve_rule", entitlements=[DEP_OPERATOR]) is True


class TestDepEndUserAuthorisation:
    """DEP End User -> user tier. Privileged actions denied; ownership-gated
    self-service actions behave like any other user-tier entitlement."""

    def test_privileged_action_denied(self):
        assert _q("dependuser", "del_rse", entitlements=[DEP_END_USER]) is False

    def test_owned_scope_did_allowed(self):
        assert (
            _q(
                "dependuser",
                "add_did",
                entitlements=[DEP_END_USER],
                scope=OWNED,
                name="file1",
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_add_replicas_requires_file_ownership_like_any_user_tier(self):
        assert (
            _q(
                "dependuser",
                "add_replicas",
                entitlements=[DEP_END_USER],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is True
        )
        assert (
            _q(
                "dependuser",
                "add_replicas",
                entitlements=[DEP_END_USER],
                rse="CERN_DATADISK",
            )
            is False
        )


class TestModelDeveloperAuthorisation:
    """Model Developer -> user tier, identical shape to DEP End User at the
    Rucio authz boundary. Where these two personas actually diverge is
    outside Rucio's authz surface entirely (design-008)."""

    def test_privileged_action_denied(self):
        assert _q("modeldeveloper", "del_rse", entitlements=[MODEL_DEVELOPER]) is False

    def test_owned_scope_did_allowed(self):
        assert (
            _q(
                "modeldeveloper",
                "add_did",
                entitlements=[MODEL_DEVELOPER],
                scope=OWNED,
                name="file1",
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_rule_self_service_allowed_for_own_account(self):
        assert (
            _q(
                "modeldeveloper",
                "add_rule",
                entitlements=[MODEL_DEVELOPER],
                account="modeldeveloper",
                locked=False,
                rse_expression="CERN_DATADISK",
                dids=[{"scope": OWNED, "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is True
        )

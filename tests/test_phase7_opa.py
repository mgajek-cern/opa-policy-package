"""
Phase 7 — e2e scenario tests against a live OPA server.

Phase 7 is the phase 6 policy, restructured to match the Authorization Service
contract (design-005). This module is self-contained: the phase 6 constants,
helpers and scenarios are copied here rather than imported, so the two phases
can diverge without one test module reaching into the other.

Three things are checked:

1. Every phase 6 scenario still holds, except where phase 7 deliberately
   changes it. The phase 6 classes below are copies; the replica classes are
   replaced, because replica actions are now ownership-gated.
2. The rules phase 6 lacked or never tested: explicit privileged-only rules
   for del_rse, add_rse_attribute and del_rse_attribute, ownership-gated
   replica rules, and cases for update_rse, attach_dids and protocols.
3. The Rego's known actions are exactly the actions with typed endpoints in
   services/authorization-service/api/openapi.yaml.

The OPA this runs against may be the testbed's own, so every test that writes
to the data bundle restores what was there.
"""

import json
import urllib.request
from pathlib import Path

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v5_policy.opa_client import query_opa

REPO_ROOT = Path(__file__).parent.parent
REGO_PATH = REPO_ROOT / "policies" / "rego" / "phase7" / "authz.rego"
OPENAPI_PATH = REPO_ROOT / "services" / "authorization-service" / "api" / "openapi.yaml"
OPA_POLICY_PATH = "vo/authz/v6/allow"

# A policy id distinct from phase 6, so loading phase 7 into a shared OPA does
# not replace the phase 6 module the Rucio suite depends on. Check what the
# second argument means in build_opa_server_fixture before relying on this.
opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/v6")

ADMIN = "urn:example:aai.example.org:group:rucio-admins:role=member"
ATLAS_PROD = "urn:example:aai.example.org:group:atlas-production:role=member"
USER = "urn:example:aai.example.org:group:rucio-users:role=member"
ATLAS_USER = "urn:example:aai.example.org:group:atlas-users:role=member"

MFA = "https://refeds.org/profile/mfa"

# Mirrors what scripts/init-phase6.sh creates: randomaccount owns a scope
# named after it and one that is not; ddmlab owns a scope whose name starts
# with "randomaccount".
OWNED = "randomaccount"
OWNED_UNNAMED = "projectdata"
FOREIGN_PREFIXED = "randomaccountleak"

RULE_ID = "1f0e3dad99908345f7439f8ffabdffc4"


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


# Entitlement-based privilege (copied from phase 6)


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
        """Reaches _is_privileged through the unknown-action catch-all."""
        assert _q("randomaccount", "approve_rule", entitlements=[USER]) is False
        assert _q("adminuser", "approve_rule", entitlements=[ADMIN]) is True


# Scope ownership (copied from phase 6)
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


# Authentication context (acr) (copied from phase 6)


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


# add_rule — rule ownership AND data ownership (design-004, copied from phase 6)
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


# del_rule / update_rule — facts resolved from the rules table
# (design-004, copied from phase 6)
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


# Rule actions left privileged by design-004 (copied from phase 6)


class TestPrivilegedRuleActions:
    def test_reduce_rule_privileged_only(self):
        assert _q("randomaccount", "reduce_rule", entitlements=[USER], rule_id=RULE_ID) is False
        assert _q("adminuser", "reduce_rule", entitlements=[ADMIN], rule_id=RULE_ID) is True

    def test_move_rule_privileged_only(self):
        assert _q("randomaccount", "move_rule", entitlements=[USER], rule_id=RULE_ID) is False
        assert _q("adminuser", "move_rule", entitlements=[ADMIN], rule_id=RULE_ID) is True


# Root bootstrap (no OIDC token) (copied from phase 6)


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


# RSE-name allowlist (copied from phase 6)
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


# Entitlement policy bundle override (runtime) (copied from phase 6)
#
# Each test sets the whole mapping it needs and the fixture restores the
# previous one, so these don't depend on declaration order or leave the
# testbed's bundle rewritten.


class TestEntitlementPolicyBundle:
    def test_custom_entitlement_granted_after_bundle_push(self, entitlement_policy):
        cms_prod = "urn:example:aai.example.org:group:cms-production:role=member"
        entitlement_policy({cms_prod: "admin", USER: "user"})
        assert _q("cmsuser", "del_rse", entitlements=[cms_prod]) is True

    def test_bundle_user_level_reaches_add_replicas(self, entitlement_policy):
        """Changed from phase 6: the request must carry owned files. The
        bundle's user tier still matters, now alongside ownership."""
        entitlement_policy({ADMIN: "admin", USER: "user"})
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=[{"scope": OWNED, "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is True
        )
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[ATLAS_USER],
                rse="CERN_DATADISK",
                files=[{"scope": OWNED, "name": "f1"}],
                owned_scopes=[OWNED],
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


# Explicit privileged-only rules (new in phase 7)
#
# Phase 6 decided these through a shared `_is_privileged` dispatch line and
# tested only del_rse. Each now has its own rule, matching its own endpoint.
# RSEs have no owning account, so there is no ownership path.

PRIVILEGED_ONLY_TYPED = [
    ("del_rse", {"rse": "CERN_DATADISK"}),
    ("add_rse_attribute", {"rse": "CERN_DATADISK", "key": "fts", "value": "https://fts:8446"}),
    ("del_rse_attribute", {"rse": "CERN_DATADISK", "key": "fts"}),
]


@pytest.mark.parametrize("action,kwargs", PRIVILEGED_ONLY_TYPED)
class TestExplicitPrivilegedRules:
    def test_admin_allowed(self, action, kwargs):
        assert _q("adminuser", action, entitlements=[ADMIN], **kwargs) is True

    def test_user_denied(self, action, kwargs):
        assert _q("randomaccount", action, entitlements=[USER], **kwargs) is False

    def test_no_entitlements_denied(self, action, kwargs):
        assert _q("randomaccount", action, entitlements=[], **kwargs) is False

    def test_root_allowed(self, action, kwargs):
        assert _root(action, **kwargs) is True

    def test_acr_enforced(self, action, kwargs, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", action, entitlements=[ADMIN], **kwargs) is False
        assert _q("adminuser", action, entitlements=[ADMIN], acr=MFA, **kwargs) is True


class TestUpdateReplicasStatesViaCatchAll:
    """No typed endpoint: the contract routes it to privileged-operations."""

    def test_admin_allowed(self):
        assert _q("adminuser", "update_replicas_states", entitlements=[ADMIN]) is True

    def test_user_denied(self):
        assert _q("randomaccount", "update_replicas_states", entitlements=[USER]) is False


# Replicas: ownership of every file's scope (changed from phase 6)
#
# Replaces phase 6's TestAddReplicasPrivilegeLevels. `files` and the
# owned_scopes resolved from them reach OPA only once the gateway passes files
# to has_permission (design-005, "Replica ownership: prerequisite"). Until
# then, the no-files cases below are what a non-privileged request looks like,
# and they deny.

OWNED_FILES = [{"scope": OWNED, "name": "f1"}, {"scope": OWNED_UNNAMED, "name": "f2"}]
BOTH_OWNED = [OWNED, OWNED_UNNAMED]


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

    def test_user_denied_on_prefix_matching_foreign_scope(self):
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=[{"scope": FOREIGN_PREFIXED, "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_user_denied_without_files(self):
        """What an unpatched gateway sends. Phase 6 allowed this."""
        assert (
            _q("randomaccount", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is False
        )

    def test_user_denied_with_empty_files(self):
        assert (
            _q(
                "randomaccount",
                "add_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=[],
                owned_scopes=[OWNED],
            )
            is False
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

    def test_owner_without_user_entitlement_denied(self):
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

    def test_replica_writes_flag_drops_entitlement_not_ownership(self, policy_leaf):
        policy_leaf("allow_replica_writes_to_allowlisted_rses", True)
        assert (
            _q(
                "carol",
                "add_replicas",
                entitlements=[],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is True
        )
        assert (
            _q(
                "carol",
                "add_replicas",
                entitlements=[],
                rse="CERN_DATADISK",
                files=[{"scope": "ddmlab", "name": "f1"}],
                owned_scopes=[],
            )
            is False
        )


class TestReplicaDelete:
    def test_admin_allowed_without_files(self):
        assert _q("adminuser", "delete_replicas", entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_root_allowed_without_files(self):
        """rucio-admin and other root API calls send no ownership facts."""
        assert _root("delete_replicas", rse="CERN_DATADISK") is True

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

    def test_user_denied_when_one_file_scope_foreign(self):
        assert (
            _q(
                "randomaccount",
                "delete_replicas",
                entitlements=[USER],
                rse="CERN_DATADISK",
                files=[{"scope": OWNED, "name": "f1"}, {"scope": "ddmlab", "name": "f2"}],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_user_denied_without_files(self):
        assert (
            _q("randomaccount", "delete_replicas", entitlements=[USER], rse="CERN_DATADISK")
            is False
        )

    def test_owner_without_user_entitlement_denied(self):
        assert (
            _q(
                "carol",
                "delete_replicas",
                entitlements=[],
                rse="CERN_DATADISK",
                files=OWNED_FILES,
                owned_scopes=BOTH_OWNED,
            )
            is False
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

    def test_ownership_path_unaffected_by_acr(self, policy_leaf):
        policy_leaf("required_acr", MFA)
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


# update_rse (untested in phase 6)


class TestUpdateRse:
    def test_admin_without_rename_allowed(self):
        assert (
            _q(
                "adminuser",
                "update_rse",
                entitlements=[ADMIN],
                rse="CERN_DATADISK",
                parameters={"availability_write": False},
            )
            is True
        )

    def test_admin_rename_to_valid_name_allowed(self):
        assert (
            _q(
                "adminuser",
                "update_rse",
                entitlements=[ADMIN],
                rse="CERN_DATADISK",
                parameters={"rse": "CERN_TAPE"},
            )
            is True
        )

    def test_admin_rename_to_invalid_name_denied(self):
        assert (
            _q(
                "adminuser",
                "update_rse",
                entitlements=[ADMIN],
                rse="CERN_DATADISK",
                parameters={"rse": "cern_bad"},
            )
            is False
        )

    def test_user_denied(self):
        assert (
            _q(
                "randomaccount",
                "update_rse",
                entitlements=[USER],
                rse="CERN_DATADISK",
                parameters={},
            )
            is False
        )


# DIDs: attach_dids (untested in phase 6) and the phase 7 changes


class TestAttachDids:
    def test_owned_parent_allowed(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids",
                entitlements=[USER],
                scope=OWNED,
                name="dataset",
                owned_scopes=[OWNED],
            )
            is True
        )

    def test_unowned_parent_denied(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids",
                entitlements=[USER],
                scope="ddmlab",
                name="dataset",
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_prefix_matching_foreign_parent_denied(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids",
                entitlements=[USER],
                scope=FOREIGN_PREFIXED,
                name="dataset",
                owned_scopes=[OWNED],
            )
            is False
        )


class TestChangedDidSemantics:
    """Decisions that deliberately differ from phase 6. Both only tighten."""

    def test_attach_dids_to_dids_requires_every_attachment_owned(self):
        """Phase 6 allowed this: one owned attachment was enough."""
        assert (
            _q(
                "randomaccount",
                "attach_dids_to_dids",
                entitlements=[USER],
                attachments=[
                    {"scope": OWNED, "name": "container", "dids": []},
                    {"scope": "ddmlab", "name": "container", "dids": []},
                ],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_attach_dids_to_dids_all_owned_allowed(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids_to_dids",
                entitlements=[USER],
                attachments=[
                    {"scope": OWNED, "name": "c1", "dids": []},
                    {"scope": OWNED_UNNAMED, "name": "c2", "dids": []},
                ],
                owned_scopes=[OWNED, OWNED_UNNAMED],
            )
            is True
        )

    def test_attach_dids_to_dids_empty_denied(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids_to_dids",
                entitlements=[USER],
                attachments=[],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_top_level_scope_no_longer_authorises_add_dids(self):
        """Phase 6's shared DID rule let an owned top-level scope override a
        foreign dids list. The gateway never sends one, but the policy no
        longer depends on that."""
        assert (
            _q(
                "randomaccount",
                "add_dids",
                entitlements=[USER],
                scope=OWNED,
                dids=[{"scope": "ddmlab", "name": "f1"}],
                owned_scopes=[OWNED],
            )
            is False
        )

    def test_top_level_scope_no_longer_authorises_attach_dids_to_dids(self):
        assert (
            _q(
                "randomaccount",
                "attach_dids_to_dids",
                entitlements=[USER],
                scope=OWNED,
                attachments=[{"scope": "ddmlab", "name": "container", "dids": []}],
                owned_scopes=[OWNED],
            )
            is False
        )


# Protocols (untested in phase 6)

PROTOCOL_ACTIONS = ["add_protocol", "update_protocol", "del_protocol"]


@pytest.mark.parametrize("action", PROTOCOL_ACTIONS)
class TestProtocols:
    def test_admin_allowlisted_scheme_allowed(self, action):
        assert (
            _q("adminuser", action, entitlements=[ADMIN], rse="CERN_DATADISK", scheme="davs")
            is True
        )

    def test_scheme_compared_case_insensitively(self, action):
        assert (
            _q("adminuser", action, entitlements=[ADMIN], rse="CERN_DATADISK", scheme="DAVS")
            is True
        )

    def test_admin_unlisted_scheme_denied(self, action):
        assert (
            _q("adminuser", action, entitlements=[ADMIN], rse="CERN_DATADISK", scheme="ftp")
            is False
        )

    def test_admin_without_scheme_allowed(self, action):
        assert _q("adminuser", action, entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_user_denied(self, action):
        assert (
            _q("randomaccount", action, entitlements=[USER], rse="CERN_DATADISK", scheme="davs")
            is False
        )

    def test_root_still_bound_by_scheme_allowlist(self, action):
        assert _root(action, rse="CERN_DATADISK", scheme="ftp") is False

    def test_bundle_scheme_list_replaces_defaults(self, action, policy_leaf):
        policy_leaf("allowed_schemes", ["ftp"])
        assert (
            _q("adminuser", action, entitlements=[ADMIN], rse="CERN_DATADISK", scheme="ftp") is True
        )
        assert (
            _q("adminuser", action, entitlements=[ADMIN], rse="CERN_DATADISK", scheme="davs")
            is False
        )


# Contract alignment
#
# The Rego's known actions must be exactly the actions with a typed endpoint.
# An action known to the Rego but missing from the contract would be sent to
# privileged-operations and rejected with 400. An action with an endpoint but
# unknown to the Rego would be decided by the catch-all rather than its own
# rule.
#
# This mapping is the dispatch table the phase 7 policy package's adapter
# uses. Keep the three in step: contract, adapter, Rego.

ACTIONS_BY_OPERATION_ID = {
    "authorizeRuleCreate": {"add_rule"},
    "authorizeRuleUpdate": {"update_rule"},
    "authorizeRuleDelete": {"del_rule"},
    "authorizeDidCreate": {"add_did", "add_dids"},
    "authorizeDidAttach": {"attach_dids", "attach_dids_to_dids"},
    "authorizeDidDetach": {"detach_dids"},
    "authorizeRseCreate": {"add_rse"},
    "authorizeRseUpdate": {"update_rse"},
    "authorizeRseDelete": {"del_rse"},
    "authorizeRseAttributeSet": {"add_rse_attribute"},
    "authorizeRseAttributeDelete": {"del_rse_attribute"},
    "authorizeProtocolCreate": {"add_protocol"},
    "authorizeProtocolUpdate": {"update_protocol"},
    "authorizeProtocolDelete": {"del_protocol"},
    "authorizeReplicaRegister": {"add_replicas"},
    "authorizeReplicaDelete": {"delete_replicas"},
}

UNTYPED_OPERATION_IDS = {"authorizePrivilegedOperation", "getHealth"}


class TestContractAlignment:
    def _contract_operation_ids(self):
        yaml = pytest.importorskip("yaml")
        spec = yaml.safe_load(OPENAPI_PATH.read_text())
        return {
            op["operationId"]
            for methods in spec["paths"].values()
            for op in methods.values()
            if isinstance(op, dict) and "operationId" in op
        }

    def _rego_known_actions(self, opa_server):
        url = f"{opa_server}/v1/data/vo/authz/v6/_all_known_actions"
        with urllib.request.urlopen(url, timeout=5) as response:
            return set(json.load(response)["result"])

    def test_every_contract_operation_is_mapped(self):
        ids = self._contract_operation_ids()
        assert ids - UNTYPED_OPERATION_IDS == set(ACTIONS_BY_OPERATION_ID)

    def test_rego_known_actions_match_typed_endpoints(self, opa_server):
        typed_actions = set().union(*ACTIONS_BY_OPERATION_ID.values())
        assert self._rego_known_actions(opa_server) == typed_actions

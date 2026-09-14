"""
Phase 4 — e2e scenario tests against a live OPA server.

`make test-opa` exports OPA_URL, so build_opa_server_fixture reuses the
testbed's own OPA rather than spawning one from REGO_PATH. Every test that
writes to the data bundle therefore restores what was there — via the
conftest fixtures, not local _put/_delete — or the next run fails somewhere
unrelated to the test that did the writing.

To run against the checked-in Rego instead of the deployed bundle:

    make test-opa PHASE=4 OPA_URL=

which needs the `opa` binary on PATH. Worth doing when a result here
disagrees with test_phase4_rucio.py — that's the signal the container's
policy has drifted from the file.
"""

from pathlib import Path
from typing import Any

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v3_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase4" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v3/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")

# Both Keycloak users in the phase 4 realm carry this same acr, so a
# required_acr deny can only be reproduced against synthetic input — hence
# TestAcrConstraint lives here and not in test_phase4_rucio.py.
MFA = "https://refeds.org/profile/mfa"

# Group paths as the wlcg-groups mapper emits them (full.path=true), which is
# also how data.vo.group_policy is keyed.
ADMIN_GROUP = "/rucio/admins"
USER_GROUP = "/rucio/users"
ATLAS_PROD_GROUP = "/atlas/production"
ATLAS_USER_GROUP = "/atlas/users"

# Deliberately not a realm group: the deployed bundle maps every path the
# realm mints, /atlas/users included, so "unmapped" has to be something no
# bundle would carry.
UNMAPPED_GROUP = "/some/other"


@pytest.fixture(autouse=True)
def _point_client(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", OPA_POLICY_PATH)


def _q(issuer: str, action: str, *, groups=None, acr=None, owned_scopes=None, **kw) -> bool:
    """Query with a token shaped the way permission.py forwards one here.

    Phase 4 forwards `groups` only — the entitlements claim is not in this
    phase's allowlist and never reaches OPA. `groups` is always present, so a
    Rego clause iterating it is safe; `acr` only when the token carries it.

    `owned_scopes` rides in kwargs rather than the token: it is resolved in
    permission.py against the scopes table, not read off a claim.
    """
    token: dict[str, Any] = {"groups": groups or []}
    if acr is not None:
        token["acr"] = acr

    kwargs = dict(kw)
    if owned_scopes is not None:
        kwargs["owned_scopes"] = owned_scopes

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
            "token": {"groups": []},
            "kwargs": kw,
        }
    )


# Group-based privilege


class TestGroupPrivilege:
    def test_admin_group_grants_del_rse(self):
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP]) is True

    def test_user_group_denies_del_rse(self):
        assert _q("alice", "del_rse", groups=[USER_GROUP]) is False

    def test_no_groups_denies_privileged_action(self):
        assert _q("alice", "del_rse", groups=[]) is False

    def test_atlas_production_is_admin(self):
        assert _q("prod", "add_rse", groups=[ATLAS_PROD_GROUP], rse="CERN_DATADISK") is True

    def test_atlas_users_is_not_admin(self):
        assert _q("alice", "add_rse", groups=[ATLAS_USER_GROUP], rse="CERN_DATADISK") is False

    def test_multiple_groups_any_admin_grants_privilege(self):
        """adminuser's real token carries both of these."""
        assert _q("adminuser", "del_rse", groups=[ATLAS_PROD_GROUP, ADMIN_GROUP]) is True

    def test_multiple_user_groups_grant_nothing(self):
        """alice's real token carries both of these, and neither maps to admin."""
        assert _q("alice", "del_rse", groups=[USER_GROUP, ATLAS_USER_GROUP]) is False

    def test_naming_rule_still_blocks_admin_groups(self):
        """Invalid RSE naming denied even with admin group — domain checks run first."""
        assert (
            _q(
                "adminuser",
                "add_rule",
                groups=[ADMIN_GROUP],
                account="adminuser",
                locked=False,
                rse_expression="cern_bad",
            )
            is False
        )

    def test_approve_rule_requires_admin_group(self):
        assert _q("alice", "approve_rule", groups=[USER_GROUP]) is False
        assert _q("adminuser", "approve_rule", groups=[ADMIN_GROUP]) is True


# Authentication-context constraint
#
# data.vo.policy.required_acr gates the OIDC privilege path only. policy_leaf
# puts back whatever the loaded bundle had rather than deleting the leaf —
# deleting would strip it from the testbed's own bundle if it ever sets one.


class TestAcrConstraint:
    def test_acr_ignored_when_not_required(self):
        """Assumes the loaded bundle sets no required_acr, which is the default.

        Don't PUT null to pin it: in Rego null is a defined value, so
        `not data.vo.policy.required_acr` would fail and every privileged
        action would be denied.
        """
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP], acr=MFA) is True
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP]) is True

    def test_admin_allowed_when_acr_matches(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP], acr=MFA) is True

    def test_admin_denied_when_acr_missing(self, policy_leaf):
        """An admin group is no longer sufficient on its own."""
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP]) is False

    def test_admin_denied_when_acr_differs(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP], acr="1") is False

    def test_root_bootstrap_unaffected_by_acr(self, policy_leaf):
        """root has no token and therefore no acr — the stack must still start."""
        policy_leaf("required_acr", MFA)
        assert _root("del_rse") is True

    def test_self_service_unaffected_by_acr(self, policy_leaf):
        """Ownership clauses don't route through _is_privileged."""
        policy_leaf("required_acr", MFA)
        assert _q("alice", "del_rule", groups=[USER_GROUP], account="alice") is True


# User group self-service actions
#
# The DID cases pass owned_scopes explicitly. permission.py resolves it from
# the scopes table before the call, so a request reaching OPA without it is
# one the server would never make.


class TestUserGroupActions:
    def test_user_can_add_own_unlocked_rule(self):
        assert (
            _q(
                "alice",
                "add_rule",
                groups=[USER_GROUP],
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="webdav",
                dst_protocol="webdav",
            )
            is True
        )

    def test_user_denied_locked_rule(self):
        assert (
            _q(
                "alice",
                "add_rule",
                groups=[USER_GROUP],
                account="alice",
                locked=True,
                rse_expression="CERN_DATADISK",
            )
            is False
        )

    def test_user_denied_rule_for_other_account(self):
        assert (
            _q(
                "alice",
                "add_rule",
                groups=[USER_GROUP],
                account="bob",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is False
        )

    def test_user_can_add_did_to_own_scope(self):
        assert (
            _q(
                "alice",
                "add_did",
                groups=[USER_GROUP],
                scope="alice.data",
                name="file1",
                owned_scopes=["alice.data"],
            )
            is True
        )

    def test_user_denied_other_scope(self):
        assert (
            _q(
                "alice",
                "add_did",
                groups=[USER_GROUP],
                scope="bob.data",
                name="file1",
                owned_scopes=["alice.data"],
            )
            is False
        )

    def test_user_can_del_own_rule(self):
        assert _q("alice", "del_rule", groups=[USER_GROUP], account="alice") is True

    def test_user_denied_del_other_rule(self):
        assert _q("alice", "del_rule", groups=[USER_GROUP], account="bob") is False

    def test_add_dids_requires_every_scope_owned(self):
        assert (
            _q(
                "alice",
                "add_dids",
                groups=[USER_GROUP],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "alice.b", "name": "f2"}],
                owned_scopes=["alice.a", "alice.b"],
            )
            is True
        )
        assert (
            _q(
                "alice",
                "add_dids",
                groups=[USER_GROUP],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "bob.data", "name": "f2"}],
                owned_scopes=["alice.a"],
            )
            is False
        )

    def test_del_protocol_without_scheme_allowed_for_admin(self):
        """del_protocol carries no scheme; the no-scheme clause covers it."""
        assert _q("adminuser", "del_protocol", groups=[ADMIN_GROUP]) is True
        assert _q("alice", "del_protocol", groups=[USER_GROUP]) is False


# add_replicas — the one rule that distinguishes a group mapped to "user"
# from a group that maps to nothing.


class TestAddReplicasPrivilegeLevels:
    def test_admin_group_allowed(self):
        assert _q("adminuser", "add_replicas", groups=[ADMIN_GROUP], rse="CERN_DATADISK") is True

    def test_user_group_allowed_on_valid_rse_name(self):
        assert _q("alice", "add_replicas", groups=[USER_GROUP], rse="CERN_DATADISK") is True

    def test_user_group_denied_on_invalid_rse_name(self):
        """The naming rule applies to the user-tier path too."""
        assert _q("alice", "add_replicas", groups=[USER_GROUP], rse="cern_bad") is False

    def test_no_group_denied(self):
        assert _q("nobody", "add_replicas", groups=[], rse="CERN_DATADISK") is False

    def test_unmapped_group_denied(self):
        assert _q("nobody", "add_replicas", groups=[UNMAPPED_GROUP], rse="CERN_DATADISK") is False


# Root bootstrap (no OIDC token)


class TestRootBootstrap:
    def test_root_allowed_del_rse(self):
        assert _root("del_rse") is True

    def test_root_allowed_add_rse_valid_name(self):
        assert _root("add_rse", rse="CERN_DATADISK") is True

    def test_root_allowed_unknown_action(self):
        assert _root("some_unknown_action") is True

    def test_root_blocked_by_naming_rule(self):
        assert (
            _root(
                "add_rule",
                account="root",
                locked=False,
                rse_expression="cern_bad",
            )
            is False
        )

    def test_non_root_empty_groups_denied_privileged(self):
        assert _q("alice", "del_rse", groups=[]) is False


# Group policy bundle override (runtime)
#
# Each test sets the whole mapping it needs and the fixture restores the
# previous one, so these no longer depend on declaration order or leave the
# testbed's bundle rewritten.


class TestGroupPolicyBundle:
    def test_custom_group_granted_after_bundle_push(self, group_policy):
        group_policy({"/cms/production": "admin", USER_GROUP: "user"})
        assert _q("cmsuser", "del_rse", groups=["/cms/production"]) is True

    def test_bundle_user_level_allows_add_replicas(self, group_policy):
        """The bundle's "user" mapping is policy, not documentation."""
        group_policy({ADMIN_GROUP: "admin", USER_GROUP: "user"})
        assert _q("alice", "add_replicas", groups=[USER_GROUP], rse="CERN_DATADISK") is True
        assert _q("alice", "add_replicas", groups=[UNMAPPED_GROUP], rse="CERN_DATADISK") is False

    def test_removed_group_loses_privilege(self, group_policy):
        group_policy({ATLAS_PROD_GROUP: "admin"})
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP]) is False
        assert _q("prod", "del_rse", groups=[ATLAS_PROD_GROUP]) is True

    def test_bundle_restored_after_override(self):
        """The fixture put the testbed's own mapping back."""
        assert _q("adminuser", "del_rse", groups=[ADMIN_GROUP]) is True

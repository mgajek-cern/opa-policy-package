"""
Phase 4 — e2e scenario tests against a live OPA server.
"""

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v3_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase4" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v3/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")

MFA = "https://refeds.org/profile/mfa"


@pytest.fixture(autouse=True)
def _point_client(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", OPA_POLICY_PATH)


def _put(opa_url: str, path: str, data: Any) -> None:
    url = f"{opa_url.rstrip('/')}/v1/data/{path}"
    req = Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urlopen(req, timeout=5):
        pass


def _delete(opa_url: str, path: str) -> None:
    """Remove a data document. Tolerates it never having been written."""
    url = f"{opa_url.rstrip('/')}/v1/data/{path}"
    try:
        with urlopen(Request(url, method="DELETE"), timeout=5):
            pass
    except HTTPError as exc:
        if exc.code != 404:
            raise


@pytest.fixture
def required_acr(opa_server):
    """Set data.vo.policy.required_acr for one test, then remove it.

    Writes the leaf rather than the whole vo/policy document, so it does not
    disturb known_rse_types or allowed_schemes if a previous test set them.
    """

    def _set(value: str) -> None:
        _put(opa_server, "vo/policy/required_acr", value)

    yield _set
    _delete(opa_server, "vo/policy/required_acr")


def _q(issuer: str, action: str, *, groups=None, acr=None, **kw) -> bool:
    token: dict[str, Any] = {"groups": groups or [], "entitlements": []}
    if acr is not None:
        token["acr"] = acr
    return query_opa(
        {
            "issuer": issuer,
            "action": action,
            "token": token,
            "kwargs": kw,
        }
    )


def _root(action: str, **kw) -> bool:
    return query_opa(
        {
            "issuer": "root",
            "action": action,
            "token": {"groups": [], "entitlements": []},
            "kwargs": kw,
        }
    )


# Group-based privilege


class TestGroupPrivilege:
    def test_admin_group_grants_del_rse(self):
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"]) is True

    def test_user_group_denies_del_rse(self):
        assert _q("alice", "del_rse", groups=["/rucio/users"]) is False

    def test_no_groups_denies_privileged_action(self):
        assert _q("alice", "del_rse", groups=[]) is False

    def test_atlas_production_is_admin(self):
        assert _q("prod", "add_rse", groups=["/atlas/production"], rse="CERN_DATADISK") is True

    def test_atlas_users_is_not_admin(self):
        assert _q("alice", "add_rse", groups=["/atlas/users"], rse="CERN_DATADISK") is False

    def test_multiple_groups_any_admin_grants_privilege(self):
        assert _q("alice", "del_rse", groups=["/rucio/users", "/rucio/admins"]) is True

    def test_naming_rule_still_blocks_admin_groups(self):
        """Invalid RSE naming denied even with admin group — domain checks run first."""
        assert (
            _q(
                "adminuser",
                "add_rule",
                groups=["/rucio/admins"],
                account="adminuser",
                locked=False,
                rse_expression="cern_bad",
            )
            is False
        )

    def test_approve_rule_requires_admin_group(self):
        assert _q("alice", "approve_rule", groups=["/rucio/users"]) is False
        assert _q("adminuser", "approve_rule", groups=["/rucio/admins"]) is True


# Authentication-context constraint
#
# data.vo.policy.required_acr gates the OIDC privilege path only. Absent by
# default, so every other test in this file is unaffected — which is also
# why the fixture removes it again.


class TestAcrConstraint:
    def test_acr_ignored_when_not_required(self):
        """Default bundle carries no required_acr — the claim is ignored."""
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"], acr=MFA) is True
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"]) is True

    def test_admin_allowed_when_acr_matches(self, required_acr):
        required_acr(MFA)
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"], acr=MFA) is True

    def test_admin_denied_when_acr_missing(self, required_acr):
        """An admin group is no longer sufficient on its own."""
        required_acr(MFA)
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"]) is False

    def test_admin_denied_when_acr_differs(self, required_acr):
        required_acr(MFA)
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"], acr="1") is False

    def test_root_bootstrap_unaffected_by_acr(self, required_acr):
        """root has no token and therefore no acr — the stack must still start."""
        required_acr(MFA)
        assert _root("del_rse") is True

    def test_self_service_unaffected_by_acr(self, required_acr):
        """Ownership clauses don't route through _is_privileged."""
        required_acr(MFA)
        assert _q("alice", "del_rule", groups=["/rucio/users"], account="alice") is True


# User group self-service actions


class TestUserGroupActions:
    def test_user_can_add_own_unlocked_rule(self):
        assert (
            _q(
                "alice",
                "add_rule",
                groups=["/rucio/users"],
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
                groups=["/rucio/users"],
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
                groups=["/rucio/users"],
                account="bob",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is False
        )

    def test_user_can_add_did_to_own_scope(self):
        assert (
            _q("alice", "add_did", groups=["/rucio/users"], scope="alice.data", name="file1")
            is True
        )

    def test_user_denied_other_scope(self):
        assert (
            _q("alice", "add_did", groups=["/rucio/users"], scope="bob.data", name="file1") is False
        )

    def test_user_can_del_own_rule(self):
        assert _q("alice", "del_rule", groups=["/rucio/users"], account="alice") is True

    def test_user_denied_del_other_rule(self):
        assert _q("alice", "del_rule", groups=["/rucio/users"], account="bob") is False

    def test_add_dids_requires_every_scope_owned(self):
        assert (
            _q(
                "alice",
                "add_dids",
                groups=["/rucio/users"],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "alice.b", "name": "f2"}],
            )
            is True
        )
        assert (
            _q(
                "alice",
                "add_dids",
                groups=["/rucio/users"],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "bob.data", "name": "f2"}],
            )
            is False
        )

    def test_del_protocol_without_scheme_allowed_for_admin(self):
        """del_protocol carries no scheme; the no-scheme clause covers it."""
        assert _q("adminuser", "del_protocol", groups=["/rucio/admins"]) is True
        assert _q("alice", "del_protocol", groups=["/rucio/users"]) is False


# add_replicas — the one rule that distinguishes a group mapped to "user"
# from a group that maps to nothing.


class TestAddReplicasPrivilegeLevels:
    def test_admin_group_allowed(self):
        assert (
            _q("adminuser", "add_replicas", groups=["/rucio/admins"], rse="CERN_DATADISK") is True
        )

    def test_user_group_allowed_on_valid_rse_name(self):
        assert _q("alice", "add_replicas", groups=["/rucio/users"], rse="CERN_DATADISK") is True

    def test_user_group_denied_on_invalid_rse_name(self):
        """The naming rule applies to the user-tier path too."""
        assert _q("alice", "add_replicas", groups=["/rucio/users"], rse="cern_bad") is False

    def test_no_group_denied(self):
        assert _q("nobody", "add_replicas", groups=[], rse="CERN_DATADISK") is False

    def test_unmapped_group_denied(self):
        assert _q("nobody", "add_replicas", groups=["/some/other"], rse="CERN_DATADISK") is False


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
# These mutate data.vo.group_policy and do not restore it, so they run last
# by declaration order. Anything added after them sees a bundle where
# /rucio/admins is no longer privileged.


class TestGroupPolicyBundle:
    def test_custom_group_granted_after_bundle_push(self, opa_server):
        _put(
            opa_server,
            "vo/group_policy",
            {
                "/cms/production": "admin",
                "/rucio/users": "user",
            },
        )
        assert _q("cmsuser", "del_rse", groups=["/cms/production"]) is True

    def test_bundle_user_level_allows_add_replicas(self, opa_server):
        """The bundle's "user" mapping is policy, not documentation."""
        assert _q("alice", "add_replicas", groups=["/rucio/users"], rse="CERN_DATADISK") is True

    def test_removed_group_loses_privilege(self, opa_server):
        _put(
            opa_server,
            "vo/group_policy",
            {
                "/atlas/production": "admin",
            },
        )
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"]) is False

    def test_remaining_group_still_privileged(self, opa_server):
        assert _q("prod", "del_rse", groups=["/atlas/production"]) is True

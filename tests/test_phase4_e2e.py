"""
Phase 4 — e2e scenario tests against a live OPA server.

Privilege is derived from token.groups (wlcg.groups) — no is_root/is_admin.

Scenario groups:
  — Group-based privilege (admin group → privileged)
  — User group actions (non-privileged but self-service still works)
  — Root bootstrap account (no token → allowed unconditionally)
  — Group policy bundle override (runtime mapping via OPA data API)
"""

import json
from pathlib import Path
from urllib.request import Request, urlopen

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v3_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "rego" / "phase4" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v3/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")


@pytest.fixture(autouse=True)
def _point_client(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", OPA_POLICY_PATH)


def _put(opa_url: str, path: str, data: dict) -> None:
    url = f"{opa_url.rstrip('/')}/v1/data/{path}"
    req = Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urlopen(req, timeout=5):
        pass


def _q(issuer: str, action: str, *, groups=None, **kw) -> bool:
    return query_opa(
        {
            "issuer": issuer,
            "action": action,
            "token": {"groups": groups or []},
            "kwargs": kw,
        }
    )


def _root(action: str, **kw) -> bool:
    return query_opa({"issuer": "root", "action": action, "token": {"groups": []}, "kwargs": kw})


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

    def test_add_replicas_requires_privilege_by_default(self):
        """No allow_replica_writes_to_allowlisted_rses in the bundle → admin only."""
        assert _q("alice", "add_replicas", groups=["/rucio/users"], rse="CERN_DATADISK") is False
        assert (
            _q("adminuser", "add_replicas", groups=["/rucio/admins"], rse="CERN_DATADISK") is True
        )

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

"""
Phase 5 — e2e scenario tests against a live OPA server.

Privilege is derived from token.entitlements (URN entitlement strings) — no
is_root/is_admin, no wlcg.groups. Same dispatch/naming/self-service logic as
Phase 4; only the privilege-derivation claim shape changed.

Scenario groups:
  — Entitlement-based privilege (admin entitlement → privileged)
  — User entitlement actions (non-privileged but self-service still works)
  — Root bootstrap account (no token → allowed unconditionally)
  — Entitlement policy bundle override (runtime mapping via OPA data API)
"""

import json
from pathlib import Path
from urllib.request import Request, urlopen

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v4_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "rego" / "phase5" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v4/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")

ADMIN = "urn:example:aai.example.org:group:rucio-admins:role=member"
ATLAS_PROD = "urn:example:aai.example.org:group:atlas-production:role=member"
USER = "urn:example:aai.example.org:group:rucio-users:role=member"
ATLAS_USER = "urn:example:aai.example.org:group:atlas-users:role=member"


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


def _q(issuer: str, action: str, *, entitlements=None, **kw) -> bool:
    return query_opa(
        {
            "issuer": issuer,
            "action": action,
            "token": {"entitlements": entitlements or []},
            "kwargs": kw,
        }
    )


def _root(action: str, **kw) -> bool:
    return query_opa(
        {"issuer": "root", "action": action, "token": {"entitlements": []}, "kwargs": kw}
    )


# Entitlement-based privilege


class TestEntitlementPrivilege:
    def test_admin_entitlement_grants_del_rse(self):
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True

    def test_user_entitlement_denies_del_rse(self):
        assert _q("alice", "del_rse", entitlements=[USER]) is False

    def test_no_entitlements_denies_privileged_action(self):
        assert _q("alice", "del_rse", entitlements=[]) is False

    def test_atlas_production_is_admin(self):
        assert _q("prod", "add_rse", entitlements=[ATLAS_PROD], rse="CERN_DATADISK") is True

    def test_atlas_users_is_not_admin(self):
        assert _q("alice", "add_rse", entitlements=[ATLAS_USER], rse="CERN_DATADISK") is False

    def test_multiple_entitlements_any_admin_grants_privilege(self):
        assert _q("alice", "del_rse", entitlements=[USER, ADMIN]) is True

    def test_naming_rule_still_blocks_admin_entitlement(self):
        """Invalid RSE naming denied even with admin entitlement — domain checks run first."""
        assert (
            _q(
                "adminuser",
                "add_rule",
                entitlements=[ADMIN],
                account="adminuser",
                locked=False,
                rse_expression="cern_bad",
            )
            is False
        )

    def test_approve_rule_requires_admin_entitlement(self):
        assert _q("alice", "approve_rule", entitlements=[USER]) is False
        assert _q("adminuser", "approve_rule", entitlements=[ADMIN]) is True


# User entitlement self-service actions

# Entitlement policy bundle override (runtime)
#
# These mutate data.vo.entitlement_policy and do not restore it, so they run
# last by declaration order. Anything added after them sees a bundle where
# ADMIN is no longer privileged.


class TestUserEntitlementActions:
    def test_user_can_add_own_unlocked_rule(self):
        assert (
            _q(
                "alice",
                "add_rule",
                entitlements=[USER],
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is True
        )

    def test_user_denied_locked_rule(self):
        assert (
            _q(
                "alice",
                "add_rule",
                entitlements=[USER],
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
                entitlements=[USER],
                account="bob",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is False
        )

    def test_user_can_add_did_to_own_scope(self):
        assert _q("alice", "add_did", entitlements=[USER], scope="alice.data", name="file1") is True

    def test_user_denied_other_scope(self):
        assert _q("alice", "add_did", entitlements=[USER], scope="bob.data", name="file1") is False

    def test_user_can_del_own_rule(self):
        assert _q("alice", "del_rule", entitlements=[USER], account="alice") is True

    def test_user_denied_del_other_rule(self):
        assert _q("alice", "del_rule", entitlements=[USER], account="bob") is False

    def test_add_replicas_requires_privilege_by_default(self):
        """No allow_replica_writes_to_allowlisted_rses in the bundle → admin only."""
        assert _q("alice", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is False
        assert _q("adminuser", "add_replicas", entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_add_dids_requires_every_scope_owned(self):
        assert (
            _q(
                "alice",
                "add_dids",
                entitlements=[USER],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "alice.b", "name": "f2"}],
            )
            is True
        )
        assert (
            _q(
                "alice",
                "add_dids",
                entitlements=[USER],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "bob.data", "name": "f2"}],
            )
            is False
        )

    def test_del_protocol_without_scheme_allowed_for_admin(self):
        """del_protocol carries no scheme; the no-scheme clause covers it."""
        assert _q("adminuser", "del_protocol", entitlements=[ADMIN]) is True
        assert _q("alice", "del_protocol", entitlements=[USER]) is False


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

    def test_non_root_empty_entitlements_denied_privileged(self):
        assert _q("alice", "del_rse", entitlements=[]) is False


# Entitlement policy bundle override (runtime)


class TestEntitlementPolicyBundle:
    def test_custom_entitlement_granted_after_bundle_push(self, opa_server):
        cms_prod = "urn:example:aai.example.org:group:cms-production:role=member"
        _put(
            opa_server,
            "vo/entitlement_policy",
            {
                cms_prod: "admin",
                USER: "user",
            },
        )
        assert _q("cmsuser", "del_rse", entitlements=[cms_prod]) is True

    def test_removed_entitlement_loses_privilege(self, opa_server):
        _put(
            opa_server,
            "vo/entitlement_policy",
            {
                ATLAS_PROD: "admin",
            },
        )
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False

    def test_remaining_entitlement_still_privileged(self, opa_server):
        assert _q("prod", "del_rse", entitlements=[ATLAS_PROD]) is True

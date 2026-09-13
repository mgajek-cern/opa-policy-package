"""
Phase 5 — e2e scenario tests against a live OPA server.
"""

import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v4_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase5" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v4/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")

ADMIN = "urn:example:aai.example.org:group:rucio-admins:role=member"
ATLAS_PROD = "urn:example:aai.example.org:group:atlas-production:role=member"
USER = "urn:example:aai.example.org:group:rucio-users:role=member"
ATLAS_USER = "urn:example:aai.example.org:group:atlas-users:role=member"

MFA = "https://refeds.org/profile/mfa"


@pytest.fixture(autouse=True)
def _point_client(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", OPA_POLICY_PATH)


def _put(opa_url: str, path: str, data) -> None:
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

    Unlike the bundle-override tests below, this restores the bundle — an
    acr requirement left in place would deny every privileged action in
    every test declared after it.
    """

    def _set(value: str) -> None:
        _put(opa_server, "vo/policy/required_acr", value)

    yield _set
    _delete(opa_server, "vo/policy/required_acr")


def _q(issuer: str, action: str, *, entitlements=None, acr=None, **kw) -> bool:
    token = {"entitlements": entitlements or [], "groups": []}
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
            "token": {"entitlements": [], "groups": []},
            "kwargs": kw,
        }
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


# Authentication context (acr)
#
# data.vo.policy.required_acr gates the OIDC privilege path only. Absent by
# default, so every other test in this module sees the pre-existing
# behaviour; the fixture restores that state afterwards.


class TestAcrConstraint:
    def test_admin_allowed_when_no_acr_required(self):
        """Default bundle carries no required_acr — the claim is ignored."""
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True
        assert _q("adminuser", "del_rse", entitlements=[ADMIN], acr=MFA) is True

    def test_admin_allowed_when_acr_matches(self, required_acr):
        required_acr(MFA)
        assert _q("adminuser", "del_rse", entitlements=[ADMIN], acr=MFA) is True

    def test_admin_denied_when_acr_missing(self, required_acr):
        """An admin entitlement is no longer sufficient on its own."""
        required_acr(MFA)
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False

    def test_admin_denied_when_acr_differs(self, required_acr):
        required_acr(MFA)
        assert (
            _q("adminuser", "del_rse", entitlements=[ADMIN], acr="urn:mace:incommon:iap:silver")
            is False
        )

    def test_root_bootstrap_unaffected_by_acr(self, required_acr):
        """root has no token and therefore no acr — gating it would strand the stack."""
        required_acr(MFA)
        assert _root("del_rse") is True

    def test_self_service_unaffected_by_acr(self, required_acr):
        """Ownership clauses don't route through _is_privileged."""
        required_acr(MFA)
        assert _q("alice", "del_rule", entitlements=[USER], account="alice") is True


# User entitlement self-service actions


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


# add_replicas — the one rule that distinguishes a "user" entitlement from
# no entitlement
#
# kwargs carry no scope, so there is no ownership signal. An entitlement
# mapped to "user" is enough on an RSE whose name passes the convention; an
# account with no mapped entitlement is not.


class TestAddReplicasPrivilegeLevels:
    def test_admin_allowed(self):
        assert _q("adminuser", "add_replicas", entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_user_level_allowed_on_valid_rse_name(self):
        assert _q("alice", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is True

    def test_user_level_denied_on_invalid_rse_name(self):
        """The naming convention still applies — "user" is not a bypass."""
        assert _q("alice", "add_replicas", entitlements=[USER], rse="cern_bad") is False

    def test_unmapped_entitlement_denied(self):
        unknown = "urn:example:aai.example.org:group:unknown:role=member"
        assert _q("carol", "add_replicas", entitlements=[unknown], rse="CERN_DATADISK") is False

    def test_no_entitlements_denied(self):
        assert _q("carol", "add_replicas", entitlements=[], rse="CERN_DATADISK") is False


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
#
# These mutate data.vo.entitlement_policy and do not restore it, so they run
# last by declaration order. Anything added after them sees a bundle where
# ADMIN is no longer privileged.


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

    def test_bundle_user_level_reaches_add_replicas(self):
        """The bundle's second tier is policy, not documentation."""
        assert _q("alice", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is True
        assert _q("alice", "add_replicas", entitlements=[ATLAS_USER], rse="CERN_DATADISK") is False

    def test_removed_entitlement_loses_privilege(self, opa_server):
        _put(
            opa_server,
            "vo/entitlement_policy",
            {
                ATLAS_PROD: "admin",
            },
        )
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False

    def test_remaining_entitlement_still_privileged(self):
        assert _q("prod", "del_rse", entitlements=[ATLAS_PROD]) is True

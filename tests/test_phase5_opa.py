"""
Phase 5 — e2e scenario tests against a live OPA server.

`make test-opa` exports OPA_URL, so build_opa_server_fixture reuses the
testbed's own OPA rather than spawning one from REGO_PATH. Every test that
writes to the data bundle therefore restores what was there — via the
conftest fixtures, not local _put/_delete — or the next run fails somewhere
unrelated to the test that did the writing.

To run against the checked-in Rego instead of the deployed bundle:

    make test-opa PHASE=5 OPA_URL=

which needs the `opa` binary on PATH. Worth doing when a result here
disagrees with test_phase5_rucio.py — that's the signal the container's
policy has drifted from the file.
"""

from pathlib import Path
from typing import Any

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v4_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase5" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v4/allow"

opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")

# Exactly the URNs the phase 5 realm puts on the two pre-created users:
# adminuser holds ADMIN + ATLAS_PROD, alice holds USER + ATLAS_USER.
ADMIN = "urn:example:aai.example.org:group:rucio-admins:role=member"
ATLAS_PROD = "urn:example:aai.example.org:group:atlas-production:role=member"
USER = "urn:example:aai.example.org:group:rucio-users:role=member"
ATLAS_USER = "urn:example:aai.example.org:group:atlas-users:role=member"

# Deliberately not a realm entitlement — "unmapped" has to be something no
# bundle would carry, rather than a URN the deployed bundle may well map.
UNMAPPED = "urn:example:aai.example.org:group:unknown:role=member"

# Both realm users carry this same acr, so a required_acr deny can only be
# reproduced against synthetic input — hence TestAcrConstraint lives here and
# not in test_phase5_rucio.py.
MFA = "https://refeds.org/profile/mfa"


@pytest.fixture(autouse=True)
def _point_client(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", OPA_POLICY_PATH)


def _q(issuer: str, action: str, *, entitlements=None, acr=None, owned_scopes=None, **kw) -> bool:
    """Query with a token shaped the way permission.py forwards one here.

    Phase 5 forwards `entitlements` only — the groups claim is not in this
    phase's allowlist and never reaches OPA. `entitlements` is always present,
    so a Rego clause iterating it is safe; `acr` only when the token carries
    it.

    `owned_scopes` rides in kwargs rather than the token: it is resolved in
    permission.py against the scopes table, not read off a claim.
    """
    token: dict[str, Any] = {"entitlements": entitlements or []}
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
            "token": {"entitlements": []},
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
        """adminuser's real token carries both of these."""
        assert _q("adminuser", "del_rse", entitlements=[ATLAS_PROD, ADMIN]) is True

    def test_multiple_user_entitlements_grant_nothing(self):
        """alice's real token carries both of these, and neither maps to admin."""
        assert _q("alice", "del_rse", entitlements=[USER, ATLAS_USER]) is False

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
# data.vo.policy.required_acr gates the OIDC privilege path only. policy_leaf
# puts back whatever the loaded bundle had rather than deleting the leaf —
# deleting would strip it from the testbed's own bundle if it ever sets one.


class TestAcrConstraint:
    def test_admin_allowed_when_no_acr_required(self):
        """Assumes the loaded bundle sets no required_acr, which is the default.

        Don't PUT null to pin it: in Rego null is a defined value, so
        `not data.vo.policy.required_acr` would fail and every privileged
        action would be denied.
        """
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True
        assert _q("adminuser", "del_rse", entitlements=[ADMIN], acr=MFA) is True

    def test_admin_allowed_when_acr_matches(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", entitlements=[ADMIN], acr=MFA) is True

    def test_admin_denied_when_acr_missing(self, policy_leaf):
        """An admin entitlement is no longer sufficient on its own."""
        policy_leaf("required_acr", MFA)
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False

    def test_admin_denied_when_acr_differs(self, policy_leaf):
        policy_leaf("required_acr", MFA)
        assert (
            _q("adminuser", "del_rse", entitlements=[ADMIN], acr="urn:mace:incommon:iap:silver")
            is False
        )

    def test_root_bootstrap_unaffected_by_acr(self, policy_leaf):
        """root has no token and therefore no acr — gating it would strand the stack."""
        policy_leaf("required_acr", MFA)
        assert _root("del_rse") is True

    def test_self_service_unaffected_by_acr(self, policy_leaf):
        """Ownership clauses don't route through _is_privileged."""
        policy_leaf("required_acr", MFA)
        assert _q("alice", "del_rule", entitlements=[USER], account="alice") is True


# User entitlement self-service actions
#
# The DID cases pass owned_scopes explicitly. permission.py resolves it from
# the scopes table before the call, so a request reaching OPA without it is
# one the server would never make.


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
        assert (
            _q(
                "alice",
                "add_did",
                entitlements=[USER],
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
                entitlements=[USER],
                scope="bob.data",
                name="file1",
                owned_scopes=["alice.data"],
            )
            is False
        )

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
                owned_scopes=["alice.a", "alice.b"],
            )
            is True
        )
        assert (
            _q(
                "alice",
                "add_dids",
                entitlements=[USER],
                dids=[{"scope": "alice.a", "name": "f1"}, {"scope": "bob.data", "name": "f2"}],
                owned_scopes=["alice.a"],
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
        assert _q("carol", "add_replicas", entitlements=[UNMAPPED], rse="CERN_DATADISK") is False

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
# Each test sets the whole mapping it needs and the fixture restores the
# previous one, so these no longer depend on declaration order or leave the
# testbed's bundle rewritten.


class TestEntitlementPolicyBundle:
    def test_custom_entitlement_granted_after_bundle_push(self, entitlement_policy):
        cms_prod = "urn:example:aai.example.org:group:cms-production:role=member"
        entitlement_policy({cms_prod: "admin", USER: "user"})
        assert _q("cmsuser", "del_rse", entitlements=[cms_prod]) is True

    def test_bundle_user_level_reaches_add_replicas(self, entitlement_policy):
        """The bundle's second tier is policy, not documentation."""
        entitlement_policy({ADMIN: "admin", USER: "user"})
        assert _q("alice", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is True
        assert _q("alice", "add_replicas", entitlements=[UNMAPPED], rse="CERN_DATADISK") is False

    def test_removed_entitlement_loses_privilege(self, entitlement_policy):
        entitlement_policy({ATLAS_PROD: "admin"})
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False
        assert _q("prod", "del_rse", entitlements=[ATLAS_PROD]) is True

    def test_bundle_restored_after_override(self):
        """The fixture put the testbed's own mapping back."""
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True

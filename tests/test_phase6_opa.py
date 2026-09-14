"""
Phase 6 — e2e scenario tests against a live OPA server.

Same entitlement model as Phase 5, plus the two things Phase 6 adds: the
testbed RSE-name allowlist, and DID ownership resolved from
`kwargs.owned_scopes` rather than a name prefix.

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

MFA = "https://refeds.org/profile/mfa"

# Mirrors what scripts/init-phase6.sh creates: randomaccount owns a scope
# named after it and one that is not; ddmlab owns a scope whose name starts
# with "randomaccount".
OWNED = "randomaccount"
OWNED_UNNAMED = "projectdata"
FOREIGN_PREFIXED = "randomaccountleak"


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
    **kw,
) -> bool:
    token = {"entitlements": entitlements or []}
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
        assert _q("randomaccount", "del_rse", entitlements=[USER]) is False

    def test_no_entitlements_denies_privileged_action(self):
        assert _q("randomaccount", "del_rse", entitlements=[]) is False

    def test_atlas_production_is_admin(self):
        assert _q("prod", "add_rse", entitlements=[ATLAS_PROD], rse="CERN_DATADISK") is True

    def test_approve_rule_requires_admin_entitlement(self):
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


# Rule self-service — account names, not scopes, so no lookup involved


class TestRuleSelfService:
    def test_user_can_add_own_unlocked_rule(self):
        assert (
            _q(
                "randomaccount",
                "add_rule",
                entitlements=[USER],
                account="randomaccount",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is True
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
            )
            is False
        )

    def test_user_can_del_own_rule(self):
        assert _q("randomaccount", "del_rule", entitlements=[USER], account="randomaccount") is True


# add_replicas — privilege levels


class TestAddReplicasPrivilegeLevels:
    def test_admin_allowed(self):
        assert _q("adminuser", "add_replicas", entitlements=[ADMIN], rse="CERN_DATADISK") is True

    def test_user_level_allowed_on_valid_rse_name(self):
        assert _q("randomaccount", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is True

    def test_user_level_denied_on_invalid_rse_name(self):
        assert _q("randomaccount", "add_replicas", entitlements=[USER], rse="cern_bad") is False

    def test_no_entitlements_denied(self):
        assert _q("carol", "add_replicas", entitlements=[], rse="CERN_DATADISK") is False


# Root bootstrap (no OIDC token)


class TestRootBootstrap:
    def test_root_allowed_del_rse(self):
        assert _root("del_rse") is True

    def test_root_allowed_unknown_action(self):
        assert _root("some_unknown_action") is True

    def test_root_allowed_did_action_without_ownership(self):
        """The transfer suite creates datasets in ddmlab as root."""
        assert _root("add_did", scope="ddmlab", name="dataset1") is True


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
        """The bundle's second tier is policy, not documentation."""
        entitlement_policy({ADMIN: "admin", USER: "user"})
        assert _q("randomaccount", "add_replicas", entitlements=[USER], rse="CERN_DATADISK") is True
        assert (
            _q("randomaccount", "add_replicas", entitlements=[ATLAS_USER], rse="CERN_DATADISK")
            is False
        )

    def test_removed_entitlement_loses_privilege(self, entitlement_policy):
        entitlement_policy({ATLAS_PROD: "admin"})
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is False
        assert _q("prod", "del_rse", entitlements=[ATLAS_PROD]) is True

    def test_bundle_restored_after_override(self):
        """The fixture put the testbed's own mapping back."""
        assert _q("adminuser", "del_rse", entitlements=[ADMIN]) is True

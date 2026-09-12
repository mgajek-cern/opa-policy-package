"""
Phase 2 — end-to-end scenario tests against a live OPA server.

These tests start OPA as a subprocess, load the real Rego policy, and drive
has_permission() through the full stack — Python client → HTTP → OPA → Rego.
No mock is used; the tests validate that the Rego policy enforces the same
rules as Phase 1.

Protocol-combo scenarios were removed: Rucio core already resolves TPC
feasibility dynamically per-RSE via the third_party_copy_read /
third_party_copy_write protocol capability flags, so the Rego policy no
longer duplicates that check.

Skips automatically if the stack isn't reachable.
"""

from pathlib import Path

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_policy.opa_client import query_opa

# OPA server fixture

REGO_PATH = Path(__file__).parent.parent / "rego" / "phase2" / "authz.rego"
opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")


@pytest.fixture(autouse=True)
def _point_client_at_opa(opa_server, monkeypatch):
    """Redirect the OPA client to the test server for every test in this module."""
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", "vo/authz/allow")


# Helper: build an input doc and query OPA directly


def _query(
    issuer: str,
    action: str,
    *,
    is_root: bool = False,
    is_admin: bool = False,
    **kwargs_fields,
) -> bool:
    return query_opa(
        {
            "issuer": issuer,
            "action": action,
            "is_root": is_root,
            "is_admin": is_admin,
            "kwargs": kwargs_fields,
        }
    )


# RSE naming (add_rule, add_rse)


class TestOPA_RseNaming:
    def test_valid_rse_name_allows_rule(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="BNL_DATADISK"
            )
            is True
        )

    def test_lowercase_rse_name_denies_rule(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="bnl_datadisk"
            )
            is False
        )

    def test_unknown_type_denies_rule(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="CERN_UNKNOWN"
            )
            is False
        )

    def test_expression_with_operators_allowed(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="site=CERN&type=DATADISK",
            )
            is True
        )

    def test_root_add_rse_valid_name(self):
        assert _query("root", "add_rse", is_root=True, rse="INFN_TAPE") is True

    def test_root_add_rse_invalid_name_denied(self):
        assert _query("root", "add_rse", is_root=True, rse="infn_tape") is False

    def test_all_known_types_accepted(self):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            result = _query("root", "add_rse", is_root=True, rse=f"CERN_{rse_type}")
            assert result is True, f"Expected CERN_{rse_type} to be accepted"


# Account privilege checks


class TestOPA_AccountChecks:
    def test_user_own_unlocked_rule_allowed(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="CERN_DATADISK"
            )
            is True
        )

    def test_user_own_locked_rule_denied(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=True, rse_expression="CERN_DATADISK"
            )
            is False
        )

    def test_user_rule_for_other_denied(self):
        assert (
            _query("alice", "add_rule", account="bob", locked=False, rse_expression="CERN_DATADISK")
            is False
        )

    def test_root_rule_for_any_account(self):
        assert (
            _query(
                "root",
                "add_rule",
                is_root=True,
                account="bob",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is True
        )

    def test_admin_rule_for_other_account(self):
        assert (
            _query(
                "adminuser",
                "add_rule",
                is_admin=True,
                account="carol",
                locked=False,
                rse_expression="CERN_DATADISK",
            )
            is True
        )

    def test_regular_user_denied_add_rse(self):
        assert _query("alice", "add_rse", rse="CERN_DATADISK") is False

    def test_regular_user_denied_del_rse(self):
        assert _query("alice", "del_rse") is False

    def test_root_allowed_del_rse(self):
        assert _query("root", "del_rse", is_root=True) is True

    def test_regular_user_denied_del_rule(self):
        assert _query("alice", "del_rule") is False

    def test_root_allowed_del_rule(self):
        assert _query("root", "del_rule", is_root=True) is True


# RSE attribute management


class TestOPA_RseAttributes:
    def test_root_add_rse_attribute_allowed(self):
        assert _query("root", "add_rse_attribute", is_root=True) is True

    def test_regular_user_denied_add_rse_attribute(self):
        assert _query("alice", "add_rse_attribute") is False

    def test_root_del_rse_attribute_allowed(self):
        assert _query("root", "del_rse_attribute", is_root=True) is True

    def test_admin_add_rse_attribute_allowed(self):
        assert _query("adminuser", "add_rse_attribute", is_admin=True) is True


# DID management


class TestOPA_DidManagement:
    def test_root_add_did_allowed(self):
        assert _query("root", "add_did", is_root=True, scope="atlas", name="dataset1") is True

    def test_scope_owner_add_did_allowed(self):
        """User can add a DID to a scope they own (scope starts with issuer name)."""
        assert _query("alice", "add_did", scope="alice.physics", name="myfile") is True

    def test_mock_scope_always_allowed(self):
        """Mock scope is open to all users for testing."""
        assert _query("alice", "add_did", scope="mock", name="testfile") is True

    def test_other_user_scope_denied(self):
        """Alice cannot add a DID to bob's scope."""
        assert _query("alice", "add_did", scope="bob.private", name="file") is False

    def test_attach_dids_scope_owner_allowed(self):
        assert _query("alice", "attach_dids", scope="alice.data", name="container") is True

    def test_detach_dids_other_scope_denied(self):
        assert _query("alice", "detach_dids", scope="carol.data", name="container") is False


# Update RSE (rename)


class TestOPA_UpdateRse:
    def test_root_rename_valid_allowed(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"rse": "NIKHEF_DATADISK"})
            is True
        )

    def test_root_rename_invalid_denied(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"rse": "nikhef_datadisk"})
            is False
        )

    def test_root_update_no_rename_allowed(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"availability_read": True})
            is True
        )

    def test_regular_user_update_rse_denied(self):
        assert _query("alice", "update_rse", parameters={"rse": "CERN_DATADISK"}) is False

"""
Phase 3 — end-to-end scenario tests against a live OPA server.

Mirrors the structure of test_phase2_e2e.py and extends it with
scenarios for newly delegated actions:
  - attach_dids_to_dids
  - del_rule / update_rule with owner self-service
  - add_protocol / del_protocol / update_protocol
  - Data-driven policy bundle overrides

Protocol-combo bundle overrides were removed: Rucio core already resolves
TPC feasibility dynamically per-RSE via the third_party_copy_read /
third_party_copy_write protocol capability flags, so no Rego rule
consumes allowed_protocol_combos anymore.

Skips automatically if the stack isn't reachable.
"""

import json
from pathlib import Path
from urllib.request import Request, urlopen

import pytest
from tests.conftest import build_opa_server_fixture

from rucio_opa_v2_policy.opa_client import query_opa

# OPA server fixture

REGO_PATH = Path(__file__).parent.parent / "phase3-opa" / "rego" / "authz.rego"
opa_server = build_opa_server_fixture(REGO_PATH, "vo/authz/allow")


@pytest.fixture(autouse=True)
def _point_client_at_opa(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", "vo/authz/v2/allow")


# Helper — push data bundle into OPA for data-driven tests


def _put_data(opa_url: str, path: str, data: dict) -> None:
    url = f"{opa_url.rstrip('/')}/v1/data/{path}"
    body = json.dumps(data).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="PUT")
    with urlopen(req, timeout=5):
        pass


# Helper — build input and query OPA


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


# RSE naming (inherited, unchanged)


class TestP3_RseNaming:
    def test_valid_name_allowed(self):
        assert _query("root", "add_rse", is_root=True, rse="CERN_DATADISK") is True

    def test_lowercase_denied(self):
        assert _query("root", "add_rse", is_root=True, rse="cern_datadisk") is False

    def test_unknown_type_denied(self):
        assert _query("root", "add_rse", is_root=True, rse="CERN_UNKNOWN") is False

    def test_all_known_types_accepted(self):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            assert _query("root", "add_rse", is_root=True, rse=f"CERN_{rse_type}") is True


# Account checks on add_rule (inherited, unchanged)


class TestP3_AccountChecks:
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


# DID actions (inherited, unchanged)


class TestP3_DidActions:
    def test_root_add_did_allowed(self):
        assert _query("root", "add_did", is_root=True, scope="atlas", name="ds1") is True

    def test_scope_owner_add_did_allowed(self):
        assert _query("alice", "add_did", scope="alice.data", name="f1") is True

    def test_mock_scope_allowed(self):
        assert _query("alice", "add_did", scope="mock", name="f1") is True

    def test_other_scope_denied(self):
        assert _query("alice", "add_did", scope="bob.data", name="f1") is False

    def test_attach_dids_scope_owner_allowed(self):
        assert _query("alice", "attach_dids", scope="alice.data", name="container") is True

    def test_detach_dids_other_scope_denied(self):
        assert _query("alice", "detach_dids", scope="carol.data", name="container") is False


# RSE management (inherited, unchanged)


class TestP3_RseManagement:
    def test_root_del_rse_allowed(self):
        assert _query("root", "del_rse", is_root=True) is True

    def test_user_del_rse_denied(self):
        assert _query("alice", "del_rse") is False

    def test_root_add_rse_attribute_allowed(self):
        assert _query("root", "add_rse_attribute", is_root=True) is True

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


# Unknown action fallback (inherited, unchanged)


class TestP3_Fallback:
    def test_root_allowed_unknown_action(self):
        assert _query("root", "some_unknown_action", is_root=True) is True

    def test_user_denied_unknown_action(self):
        assert _query("alice", "some_unknown_action") is False


# attach_dids_to_dids (Phase 3 — rucio-it-tools gap closed)


class TestP3_AttachDidsToDids:
    """
    attach_dids_to_dids is the bulk attach used by rucio_it_register.py to
    build the container/dataset/file DID hierarchy. It was absent from
    _did_actions in Phase 2.
    """

    def test_root_attach_dids_to_dids_allowed(self):
        assert (
            _query("root", "attach_dids_to_dids", is_root=True, scope="atlas", attachments=[])
            is True
        )

    def test_scope_owner_attach_dids_to_dids_allowed(self):
        """Issuer owns the scope — allowed without privilege."""
        assert (
            _query(
                "alice",
                "attach_dids_to_dids",
                scope="alice.data",
                attachments=[
                    {
                        "scope": "alice.data",
                        "name": "container",
                        "dids": [{"scope": "alice.data", "name": "dataset/"}],
                    }
                ],
            )
            is True
        )

    def test_mock_scope_attach_allowed(self):
        assert (
            _query(
                "alice",
                "attach_dids_to_dids",
                scope="mock",
                attachments=[
                    {"scope": "mock", "name": "c", "dids": [{"scope": "mock", "name": "ds/"}]}
                ],
            )
            is True
        )

    def test_other_scope_attach_denied(self):
        """Alice cannot attach DIDs in bob's scope."""
        assert (
            _query(
                "alice",
                "attach_dids_to_dids",
                scope="bob.data",
                attachments=[
                    {
                        "scope": "bob.data",
                        "name": "container",
                        "dids": [{"scope": "bob.data", "name": "dataset/"}],
                    }
                ],
            )
            is False
        )

    def test_admin_attach_any_scope_allowed(self):
        assert (
            _query(
                "adminuser",
                "attach_dids_to_dids",
                is_admin=True,
                scope="carol.data",
                attachments=[
                    {
                        "scope": "carol.data",
                        "name": "c",
                        "dids": [{"scope": "carol.data", "name": "ds/"}],
                    }
                ],
            )
            is True
        )


# del_rule / update_rule owner self-service (Phase 3 addition)


class TestP3_RuleOwnerSelfService:
    """
    In Phase 2, del_rule and update_rule were privileged-only.
    Phase 3 allows the rule owner (kwargs.account == issuer) to act on
    their own rules without requiring root or admin.
    """

    def test_owner_del_own_rule_allowed(self):
        """Rule owner can delete their own rule."""
        assert _query("alice", "del_rule", account="alice") is True

    def test_non_owner_del_rule_denied(self):
        """Alice cannot delete a rule owned by bob."""
        assert _query("alice", "del_rule", account="bob") is False

    def test_root_del_any_rule_allowed(self):
        """Root can delete any rule regardless of owner."""
        assert _query("root", "del_rule", is_root=True, account="bob") is True

    def test_admin_del_any_rule_allowed(self):
        assert _query("adminuser", "del_rule", is_admin=True, account="carol") is True

    def test_owner_update_own_rule_allowed(self):
        assert _query("alice", "update_rule", account="alice") is True

    def test_non_owner_update_rule_denied(self):
        assert _query("alice", "update_rule", account="bob") is False

    def test_root_update_any_rule_allowed(self):
        assert _query("root", "update_rule", is_root=True, account="carol") is True

    def test_approve_rule_still_privileged_only(self):
        """approve_rule is not self-service — requires privilege."""
        assert _query("alice", "approve_rule", account="alice") is False
        assert _query("root", "approve_rule", is_root=True) is True


# Protocol management with scheme allowlist (Phase 3 addition)


class TestP3_ProtocolManagement:
    """
    add_protocol / del_protocol / update_protocol are now delegated to OPA.
    Only privileged accounts may call them, and only for allowed schemes.
    """

    def test_root_add_allowed_scheme_davs(self):
        assert _query("root", "add_protocol", is_root=True, scheme="davs") is True

    def test_root_add_allowed_scheme_s3(self):
        assert _query("root", "add_protocol", is_root=True, scheme="s3") is True

    def test_root_add_allowed_scheme_root(self):
        assert _query("root", "add_protocol", is_root=True, scheme="root") is True

    def test_root_add_allowed_scheme_xrdhttp(self):
        assert _query("root", "add_protocol", is_root=True, scheme="xrdhttp") is True

    def test_root_add_unknown_scheme_denied(self):
        """ftp is not in the allowed scheme set."""
        assert _query("root", "add_protocol", is_root=True, scheme="ftp") is False

    def test_user_add_protocol_denied(self):
        """Non-privileged users cannot register protocols regardless of scheme."""
        assert _query("alice", "add_protocol", scheme="davs") is False

    def test_root_del_protocol_allowed_scheme(self):
        assert _query("root", "del_protocol", is_root=True, scheme="davs") is True

    def test_root_update_protocol_allowed_scheme(self):
        assert _query("root", "update_protocol", is_root=True, scheme="https") is True

    def test_scheme_check_case_insensitive(self):
        """Scheme comparison is lowercased — DAVS should match davs."""
        assert _query("root", "add_protocol", is_root=True, scheme="DAVS") is True

    def test_unknown_scheme_denied_even_for_root(self):
        assert _query("root", "add_protocol", is_root=True, scheme="srm") is False


# Data-driven policy bundle overrides (Phase 3 addition)


class TestP3_DataDrivenBundle:
    """
    Verify that pushing a custom data bundle to OPA at runtime overrides the
    hardcoded defaults. This exercises the data.vo.policy.* lookups in Rego.

    Only known_rse_types and allowed_schemes remain data-driven —
    allowed_protocol_combos was removed along with the Rego rule that
    consumed it.
    """

    def test_custom_rse_type_accepted_after_bundle_push(self, opa_server):
        """Push a custom RSE type into the bundle and verify it is accepted."""
        _put_data(
            opa_server,
            "vo/policy",
            {
                "known_rse_types": [
                    "DATADISK",
                    "SCRATCHDISK",
                    "LOCALGROUPDISK",
                    "TAPE",
                    "USERDISK",
                    "EXPERIMENTDISK",
                ],
            },
        )
        assert _query("root", "add_rse", is_root=True, rse="CERN_EXPERIMENTDISK") is True

    def test_removed_rse_type_denied_after_bundle_push(self, opa_server):
        """Push a restricted RSE type set and verify TAPE is now rejected."""
        _put_data(
            opa_server,
            "vo/policy",
            {
                "known_rse_types": ["DATADISK"],
            },
        )
        assert _query("root", "add_rse", is_root=True, rse="CERN_TAPE") is False

    def test_custom_scheme_allowlist_accepted(self, opa_server):
        """Add srm to allowed schemes via bundle."""
        _put_data(
            opa_server,
            "vo/policy",
            {
                "known_rse_types": [
                    "DATADISK",
                    "SCRATCHDISK",
                    "LOCALGROUPDISK",
                    "TAPE",
                    "USERDISK",
                ],
                "allowed_schemes": ["davs", "s3", "https", "root", "xrdhttp", "gsiftp", "srm"],
            },
        )
        assert _query("root", "add_protocol", is_root=True, scheme="srm") is True

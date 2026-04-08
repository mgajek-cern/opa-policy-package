"""
Phase 3 — end-to-end scenario tests against a live OPA server.

Mirrors the structure of test_phase2_e2e_scenarios.py and extends it with
scenarios for newly delegated actions:
  - attach_dids_to_dids  (Group G — rucio-it-tools gap)
  - del_rule / update_rule with owner self-service  (Group H)
  - add_protocol / del_protocol / update_protocol  (Group I)
  - Data-driven policy bundle overrides  (Group J)

Tests are automatically skipped when:
  - the `opa` binary is not on PATH, OR
  - OPA fails to start within the timeout

Run manually:
  pytest tests/test_phase3_e2e_scenarios.py -v

Docker alternative:
  cd phase3-opa/docker && docker compose up -d
  OPA_URL=http://localhost:8181 pytest tests/test_phase3_e2e_scenarios.py -v
  docker compose down
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from rucio_opa_v2_policy.opa_client import query_opa

# ---------------------------------------------------------------------------
# OPA server fixture
# ---------------------------------------------------------------------------

REGO_PATH = Path(__file__).parent.parent / "phase3-opa" / "rego" / "authz.rego"
OPA_STARTUP_TIMEOUT = 10


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _opa_available() -> bool:
    return shutil.which("opa") is not None


def _wait_for_opa(port: int, timeout: float = OPA_STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def opa_server():
    """
    Resolve a running OPA server for the duration of this test module.

    Priority:
      1. OPA_URL env var → use that server directly (Docker workflow).
      2. `opa` binary on PATH → spawn a local subprocess.
      3. Neither → skip the module.
    """
    import urllib.request as _ur

    external_url = os.environ.get("OPA_URL", "").strip()
    if external_url:
        try:
            _ur.urlopen(f"{external_url.rstrip('/')}/health", timeout=3)
        except Exception as exc:
            pytest.skip(f"OPA_URL={external_url} is not reachable: {exc}")
        yield external_url
        return

    if not _opa_available():
        pytest.skip(
            "'opa' binary not found on PATH and OPA_URL is not set. "
            "Install OPA or set OPA_URL to a running instance."
        )

    port = _free_port()
    proc = subprocess.Popen(
        [
            "opa",
            "run",
            "--server",
            "--log-level",
            "error",
            f"--addr=127.0.0.1:{port}",
            str(REGO_PATH),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not _wait_for_opa(port):
        proc.terminate()
        pytest.skip(f"OPA did not start on port {port} within {OPA_STARTUP_TIMEOUT}s")

    yield f"http://127.0.0.1:{port}"
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)


@pytest.fixture(autouse=True)
def _point_client_at_opa(opa_server, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", "vo/authz/v2/allow")


# ---------------------------------------------------------------------------
# Helper — push data bundle into OPA for data-driven tests
# ---------------------------------------------------------------------------


def _put_data(opa_url: str, path: str, data: dict) -> None:
    url = f"{opa_url.rstrip('/')}/v1/data/{path}"
    body = json.dumps(data).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="PUT")
    with urlopen(req, timeout=5):
        pass


# ---------------------------------------------------------------------------
# Helper — build input and query OPA
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Group A — Protocol combos (inherited from Phase 2, unchanged)
# ---------------------------------------------------------------------------


class TestP3_ProtocolCombos:
    """Verify the five allowed TPC paths still hold in Phase 3."""

    def test_A1_webdav_to_webdav_allowed(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="webdav",
                dst_protocol="webdav",
            )
            is True
        )

    def test_A2_s3_to_webdav_allowed(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="s3",
                dst_protocol="webdav",
            )
            is True
        )

    def test_A3_xrdhttp_to_webdav_allowed(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="xrdhttp",
                dst_protocol="webdav",
            )
            is True
        )

    def test_A4_s3_to_xrdhttp_allowed(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="s3",
                dst_protocol="xrdhttp",
            )
            is True
        )

    def test_A5_xrdhttp_to_xrdhttp_allowed(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="xrdhttp",
                dst_protocol="xrdhttp",
            )
            is True
        )

    def test_A6_webdav_to_s3_denied(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="webdav",
                dst_protocol="s3",
            )
            is False
        )

    def test_A7_s3_to_s3_denied_even_for_root(self):
        assert (
            _query(
                "root",
                "add_rule",
                is_root=True,
                account="root",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="s3",
                dst_protocol="s3",
            )
            is False
        )


# ---------------------------------------------------------------------------
# Group B — RSE naming (inherited, unchanged)
# ---------------------------------------------------------------------------


class TestP3_RseNaming:
    def test_B1_valid_name_allowed(self):
        assert _query("root", "add_rse", is_root=True, rse="CERN_DATADISK") is True

    def test_B2_lowercase_denied(self):
        assert _query("root", "add_rse", is_root=True, rse="cern_datadisk") is False

    def test_B3_unknown_type_denied(self):
        assert _query("root", "add_rse", is_root=True, rse="CERN_UNKNOWN") is False

    def test_B4_all_known_types_accepted(self):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            assert _query("root", "add_rse", is_root=True, rse=f"CERN_{rse_type}") is True


# ---------------------------------------------------------------------------
# Group C — Account checks on add_rule (inherited, unchanged)
# ---------------------------------------------------------------------------


class TestP3_AccountChecks:
    def test_C1_user_own_unlocked_rule_allowed(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="CERN_DATADISK"
            )
            is True
        )

    def test_C2_user_own_locked_rule_denied(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=True, rse_expression="CERN_DATADISK"
            )
            is False
        )

    def test_C3_user_rule_for_other_denied(self):
        assert (
            _query("alice", "add_rule", account="bob", locked=False, rse_expression="CERN_DATADISK")
            is False
        )

    def test_C4_root_rule_for_any_account(self):
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


# ---------------------------------------------------------------------------
# Group D — DID actions (inherited, unchanged)
# ---------------------------------------------------------------------------


class TestP3_DidActions:
    def test_D1_root_add_did_allowed(self):
        assert _query("root", "add_did", is_root=True, scope="atlas", name="ds1") is True

    def test_D2_scope_owner_add_did_allowed(self):
        assert _query("alice", "add_did", scope="alice.data", name="f1") is True

    def test_D3_mock_scope_allowed(self):
        assert _query("alice", "add_did", scope="mock", name="f1") is True

    def test_D4_other_scope_denied(self):
        assert _query("alice", "add_did", scope="bob.data", name="f1") is False

    def test_D5_attach_dids_scope_owner_allowed(self):
        assert _query("alice", "attach_dids", scope="alice.data", name="container") is True

    def test_D6_detach_dids_other_scope_denied(self):
        assert _query("alice", "detach_dids", scope="carol.data", name="container") is False


# ---------------------------------------------------------------------------
# Group E — RSE management (inherited, unchanged)
# ---------------------------------------------------------------------------


class TestP3_RseManagement:
    def test_E1_root_del_rse_allowed(self):
        assert _query("root", "del_rse", is_root=True) is True

    def test_E2_user_del_rse_denied(self):
        assert _query("alice", "del_rse") is False

    def test_E3_root_add_rse_attribute_allowed(self):
        assert _query("root", "add_rse_attribute", is_root=True) is True

    def test_E4_root_rename_valid_allowed(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"rse": "NIKHEF_DATADISK"})
            is True
        )

    def test_E5_root_rename_invalid_denied(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"rse": "nikhef_datadisk"})
            is False
        )


# ---------------------------------------------------------------------------
# Group F — Unknown action fallback (inherited, unchanged)
# ---------------------------------------------------------------------------


class TestP3_Fallback:
    def test_F1_root_allowed_unknown_action(self):
        assert _query("root", "some_unknown_action", is_root=True) is True

    def test_F2_user_denied_unknown_action(self):
        assert _query("alice", "some_unknown_action") is False


# ---------------------------------------------------------------------------
# Group G — attach_dids_to_dids (Phase 3 — rucio-it-tools gap closed)
# ---------------------------------------------------------------------------


class TestP3_AttachDidsToDids:
    """
    attach_dids_to_dids is the bulk attach used by rucio_it_register.py to
    build the container/dataset/file DID hierarchy. It was absent from
    _did_actions in Phase 2.
    """

    def test_G1_root_attach_dids_to_dids_allowed(self):
        assert (
            _query("root", "attach_dids_to_dids", is_root=True, scope="atlas", attachments=[])
            is True
        )

    def test_G2_scope_owner_attach_dids_to_dids_allowed(self):
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

    def test_G3_mock_scope_attach_allowed(self):
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

    def test_G4_other_scope_attach_denied(self):
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

    def test_G5_admin_attach_any_scope_allowed(self):
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


# ---------------------------------------------------------------------------
# Group H — del_rule / update_rule owner self-service (Phase 3 addition)
# ---------------------------------------------------------------------------


class TestP3_RuleOwnerSelfService:
    """
    In Phase 2, del_rule and update_rule were privileged-only.
    Phase 3 allows the rule owner (kwargs.account == issuer) to act on
    their own rules without requiring root or admin.
    """

    def test_H1_owner_del_own_rule_allowed(self):
        """Rule owner can delete their own rule."""
        assert _query("alice", "del_rule", account="alice") is True

    def test_H2_non_owner_del_rule_denied(self):
        """Alice cannot delete a rule owned by bob."""
        assert _query("alice", "del_rule", account="bob") is False

    def test_H3_root_del_any_rule_allowed(self):
        """Root can delete any rule regardless of owner."""
        assert _query("root", "del_rule", is_root=True, account="bob") is True

    def test_H4_admin_del_any_rule_allowed(self):
        assert _query("adminuser", "del_rule", is_admin=True, account="carol") is True

    def test_H5_owner_update_own_rule_allowed(self):
        assert _query("alice", "update_rule", account="alice") is True

    def test_H6_non_owner_update_rule_denied(self):
        assert _query("alice", "update_rule", account="bob") is False

    def test_H7_root_update_any_rule_allowed(self):
        assert _query("root", "update_rule", is_root=True, account="carol") is True

    def test_H8_approve_rule_still_privileged_only(self):
        """approve_rule is not self-service — requires privilege."""
        assert _query("alice", "approve_rule", account="alice") is False
        assert _query("root", "approve_rule", is_root=True) is True


# ---------------------------------------------------------------------------
# Group I — Protocol management with scheme allowlist (Phase 3 addition)
# ---------------------------------------------------------------------------


class TestP3_ProtocolManagement:
    """
    add_protocol / del_protocol / update_protocol are now delegated to OPA.
    Only privileged accounts may call them, and only for allowed schemes.
    """

    def test_I1_root_add_allowed_scheme_davs(self):
        assert _query("root", "add_protocol", is_root=True, scheme="davs") is True

    def test_I2_root_add_allowed_scheme_s3(self):
        assert _query("root", "add_protocol", is_root=True, scheme="s3") is True

    def test_I3_root_add_allowed_scheme_root(self):
        assert _query("root", "add_protocol", is_root=True, scheme="root") is True

    def test_I4_root_add_allowed_scheme_xrdhttp(self):
        assert _query("root", "add_protocol", is_root=True, scheme="xrdhttp") is True

    def test_I5_root_add_unknown_scheme_denied(self):
        """ftp is not in the allowed scheme set."""
        assert _query("root", "add_protocol", is_root=True, scheme="ftp") is False

    def test_I6_user_add_protocol_denied(self):
        """Non-privileged users cannot register protocols regardless of scheme."""
        assert _query("alice", "add_protocol", scheme="davs") is False

    def test_I7_root_del_protocol_allowed_scheme(self):
        assert _query("root", "del_protocol", is_root=True, scheme="davs") is True

    def test_I8_root_update_protocol_allowed_scheme(self):
        assert _query("root", "update_protocol", is_root=True, scheme="https") is True

    def test_I9_scheme_check_case_insensitive(self):
        """Scheme comparison is lowercased — DAVS should match davs."""
        assert _query("root", "add_protocol", is_root=True, scheme="DAVS") is True

    def test_I10_unknown_scheme_denied_even_for_root(self):
        assert _query("root", "add_protocol", is_root=True, scheme="srm") is False


# ---------------------------------------------------------------------------
# Group J — Data-driven policy bundle overrides (Phase 3 addition)
# ---------------------------------------------------------------------------


class TestP3_DataDrivenBundle:
    """
    Verify that pushing a custom data bundle to OPA at runtime overrides the
    hardcoded defaults. This exercises the data.vo.policy.* lookups in Rego.
    """

    def test_J1_custom_rse_type_accepted_after_bundle_push(self, opa_server):
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
                "allowed_protocol_combos": [
                    ["webdav", "webdav"],
                    ["s3", "webdav"],
                    ["xrdhttp", "webdav"],
                    ["s3", "xrdhttp"],
                    ["xrdhttp", "xrdhttp"],
                ],
                "allowed_schemes": ["davs", "s3", "https", "root", "xrdhttp", "gsiftp"],
            },
        )
        assert _query("root", "add_rse", is_root=True, rse="CERN_EXPERIMENTDISK") is True

    def test_J2_removed_rse_type_denied_after_bundle_push(self, opa_server):
        """Push a restricted RSE type set and verify TAPE is now rejected."""
        _put_data(
            opa_server,
            "vo/policy",
            {
                "known_rse_types": ["DATADISK"],
                "allowed_protocol_combos": [
                    ["webdav", "webdav"],
                    ["s3", "webdav"],
                    ["xrdhttp", "webdav"],
                    ["s3", "xrdhttp"],
                    ["xrdhttp", "xrdhttp"],
                ],
                "allowed_schemes": ["davs", "s3", "https", "root", "xrdhttp", "gsiftp"],
            },
        )
        assert _query("root", "add_rse", is_root=True, rse="CERN_TAPE") is False

    def test_J3_custom_protocol_combo_accepted_after_bundle_push(self, opa_server):
        """Add webdav→s3 to allowed combos via bundle and verify it is now accepted."""
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
                "allowed_protocol_combos": [
                    ["webdav", "webdav"],
                    ["s3", "webdav"],
                    ["xrdhttp", "webdav"],
                    ["s3", "xrdhttp"],
                    ["xrdhttp", "xrdhttp"],
                    ["webdav", "s3"],  # added for this VO's specific setup
                ],
                "allowed_schemes": ["davs", "s3", "https", "root", "xrdhttp", "gsiftp"],
            },
        )
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="webdav",
                dst_protocol="s3",
            )
            is True
        )

    def test_J4_custom_scheme_allowlist_accepted(self, opa_server):
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
                "allowed_protocol_combos": [
                    ["webdav", "webdav"],
                    ["s3", "webdav"],
                    ["xrdhttp", "webdav"],
                    ["s3", "xrdhttp"],
                    ["xrdhttp", "xrdhttp"],
                ],
                "allowed_schemes": ["davs", "s3", "https", "root", "xrdhttp", "gsiftp", "srm"],
            },
        )
        assert _query("root", "add_protocol", is_root=True, scheme="srm") is True

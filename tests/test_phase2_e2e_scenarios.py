"""
Phase 2 — end-to-end scenario tests against a live OPA server.

These tests start OPA as a subprocess, load the real Rego policy, and drive
has_permission() through the full stack — Python client → HTTP → OPA → Rego.
No mock is used; the tests validate that the Rego policy enforces the same
rules as Phase 1.

Tests are automatically skipped when:
  - the `opa` binary is not on PATH, OR
  - OPA fails to start within the timeout

Run manually when OPA is installed:
  pytest tests/test_phase2_e2e_scenarios.py -v

Docker alternative (no local OPA binary needed):
  cd phase2-opa/docker && docker compose up -d
  OPA_URL=http://localhost:8181 pytest tests/test_phase2_e2e_scenarios.py -v
  docker compose down
"""

import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

from rucio_opa_policy.opa_client import query_opa

# ---------------------------------------------------------------------------
# OPA server fixture
# ---------------------------------------------------------------------------

REGO_PATH = Path(__file__).parent.parent / "phase2-opa" / "rego" / "authz.rego"
OPA_STARTUP_TIMEOUT = 10  # seconds


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
      1. OPA_URL env var is set → use that server directly (Docker workflow).
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
            "Install OPA or run: cd phase2-opa/docker && docker compose up -d && "
            "OPA_URL=http://localhost:8181 pytest tests/test_phase2_e2e_scenarios.py"
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

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)


@pytest.fixture(autouse=True)
def _point_client_at_opa(opa_server, monkeypatch):
    """Redirect the OPA client to the test server for every test in this module."""
    monkeypatch.setenv("OPA_URL", opa_server)
    monkeypatch.setenv("OPA_POLICY_PATH", "vo/authz/allow")


# ---------------------------------------------------------------------------
# Helper: build an input doc and query OPA directly
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
# Scenario group A — Protocol combos (add_rule)
# ---------------------------------------------------------------------------


class TestOPA_ProtocolCombos:
    """Mirror of Phase 1 Scenario A — now evaluated by real Rego."""

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
        """WebDAV destination can TPC-pull from S3 source."""
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="BNL_DATADISK",
                source_protocol="s3",
                dst_protocol="webdav",
            )
            is True
        )

    def test_A3_xrdhttp_to_webdav_allowed(self):
        """WebDAV destination can TPC-pull from XrdHTTP source."""
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="DESY_TAPE",
                source_protocol="xrdhttp",
                dst_protocol="webdav",
            )
            is True
        )

    def test_A4_webdav_to_s3_denied(self):
        """S3 cannot act as a TPC destination — requires FTS streaming."""
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

    def test_A5_xrdhttp_to_s3_denied(self):
        """S3 cannot act as a TPC destination — requires FTS streaming."""
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="xrdhttp",
                dst_protocol="s3",
            )
            is False
        )

    def test_A6_s3_to_s3_denied(self):
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="s3",
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

    def test_A8_no_protocol_hints_allowed(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="CERN_DATADISK"
            )
            is True
        )

    def test_A9_case_insensitive(self):
        """Protocol names are normalised to lowercase before checking."""
        assert (
            _query(
                "alice",
                "add_rule",
                account="alice",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="S3",
                dst_protocol="WEBDAV",
            )
            is True
        )


# ---------------------------------------------------------------------------
# Scenario group B — RSE naming (add_rule, add_rse)
# ---------------------------------------------------------------------------


class TestOPA_RseNaming:
    def test_B1_valid_rse_name_allows_rule(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="BNL_DATADISK"
            )
            is True
        )

    def test_B2_lowercase_rse_name_denies_rule(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="bnl_datadisk"
            )
            is False
        )

    def test_B3_unknown_type_denies_rule(self):
        assert (
            _query(
                "alice", "add_rule", account="alice", locked=False, rse_expression="CERN_UNKNOWN"
            )
            is False
        )

    def test_B4_expression_with_operators_allowed(self):
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

    def test_B5_root_add_rse_valid_name(self):
        assert _query("root", "add_rse", is_root=True, rse="INFN_TAPE") is True

    def test_B6_root_add_rse_invalid_name_denied(self):
        assert _query("root", "add_rse", is_root=True, rse="infn_tape") is False

    def test_B7_all_known_types_accepted(self):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            result = _query("root", "add_rse", is_root=True, rse=f"CERN_{rse_type}")
            assert result is True, f"Expected CERN_{rse_type} to be accepted"


# ---------------------------------------------------------------------------
# Scenario group C — Account privilege checks
# ---------------------------------------------------------------------------


class TestOPA_AccountChecks:
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

    def test_C5_admin_rule_for_other_account(self):
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

    def test_C6_regular_user_denied_add_rse(self):
        assert _query("alice", "add_rse", rse="CERN_DATADISK") is False

    def test_C7_regular_user_denied_del_rse(self):
        assert _query("alice", "del_rse") is False

    def test_C8_root_allowed_del_rse(self):
        assert _query("root", "del_rse", is_root=True) is True

    def test_C9_regular_user_denied_del_rule(self):
        assert _query("alice", "del_rule") is False

    def test_C10_root_allowed_del_rule(self):
        assert _query("root", "del_rule", is_root=True) is True


# ---------------------------------------------------------------------------
# Scenario group D — RSE attribute management
# ---------------------------------------------------------------------------


class TestOPA_RseAttributes:
    def test_D1_root_add_rse_attribute_allowed(self):
        assert _query("root", "add_rse_attribute", is_root=True) is True

    def test_D2_regular_user_denied_add_rse_attribute(self):
        assert _query("alice", "add_rse_attribute") is False

    def test_D3_root_del_rse_attribute_allowed(self):
        assert _query("root", "del_rse_attribute", is_root=True) is True

    def test_D4_admin_add_rse_attribute_allowed(self):
        assert _query("adminuser", "add_rse_attribute", is_admin=True) is True


# ---------------------------------------------------------------------------
# Scenario group E — DID management
# ---------------------------------------------------------------------------


class TestOPA_DidManagement:
    def test_E1_root_add_did_allowed(self):
        assert _query("root", "add_did", is_root=True, scope="atlas", name="dataset1") is True

    def test_E2_scope_owner_add_did_allowed(self):
        """User can add a DID to a scope they own (scope starts with issuer name)."""
        assert _query("alice", "add_did", scope="alice.physics", name="myfile") is True

    def test_E3_mock_scope_always_allowed(self):
        """Mock scope is open to all users for testing."""
        assert _query("alice", "add_did", scope="mock", name="testfile") is True

    def test_E4_other_user_scope_denied(self):
        """Alice cannot add a DID to bob's scope."""
        assert _query("alice", "add_did", scope="bob.private", name="file") is False

    def test_E5_attach_dids_scope_owner_allowed(self):
        assert _query("alice", "attach_dids", scope="alice.data", name="container") is True

    def test_E6_detach_dids_other_scope_denied(self):
        assert _query("alice", "detach_dids", scope="carol.data", name="container") is False


# ---------------------------------------------------------------------------
# Scenario group F — Update RSE (rename)
# ---------------------------------------------------------------------------


class TestOPA_UpdateRse:
    def test_F1_root_rename_valid_allowed(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"rse": "NIKHEF_DATADISK"})
            is True
        )

    def test_F2_root_rename_invalid_denied(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"rse": "nikhef_datadisk"})
            is False
        )

    def test_F3_root_update_no_rename_allowed(self):
        assert (
            _query("root", "update_rse", is_root=True, parameters={"availability_read": True})
            is True
        )

    def test_F4_regular_user_update_rse_denied(self):
        assert _query("alice", "update_rse", parameters={"rse": "CERN_DATADISK"}) is False

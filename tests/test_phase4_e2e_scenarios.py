"""
Phase 4 — e2e scenario tests against a live OPA server.

Privilege is derived from token.groups (wlcg.groups) — no is_root/is_admin.

Run against live OPA (recommended):
    cd phase4-opa/docker && docker compose up -d opa opa-init && cd ../..
    OPA_URL=http://localhost:8181 python3 -m pytest tests4/test_phase4_e2e_scenarios.py -v

Scenario groups:
  K — Group-based privilege (admin group → privileged)
  L — User group actions (non-privileged but self-service still works)
  M — Root bootstrap account (no token → allowed unconditionally)
  N — Group policy bundle override (runtime mapping via OPA data API)
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

from rucio_opa_v3_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "phase4-opa" / "rego" / "authz.rego"
OPA_STARTUP_TIMEOUT = 10
OPA_POLICY_PATH = "vo/authz/v3/allow"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_opa(port: int, timeout: float = OPA_STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


DEFAULT_GROUP_POLICY = {
    "/rucio/admins": "admin",
    "/atlas/production": "admin",
    "/rucio/users": "user",
    "/atlas/users": "user",
}


def _seed_group_policy(opa_url: str) -> None:
    """Push the default group policy so K-tests are not affected by N-test state."""
    _put(opa_url, "vo/group_policy", DEFAULT_GROUP_POLICY)


@pytest.fixture(scope="module")
def opa_server():
    import urllib.request as _ur

    external_url = os.environ.get("OPA_URL", "").strip()
    if external_url:
        try:
            _ur.urlopen(f"{external_url.rstrip('/')}/health", timeout=3)
        except Exception as exc:
            pytest.skip(f"OPA_URL={external_url} not reachable: {exc}")
        _seed_group_policy(external_url)
        yield external_url
        return

    opa_bin = shutil.which("opa") or "opa"
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603
        [
            opa_bin,
            "run",
            "--server",
            "--log-level",
            "error",
            f"--addr=127.0.0.1:{port}",
            str(REGO_PATH),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # noqa: S603
    if not _wait_for_opa(port):
        proc.terminate()
        pytest.skip(f"OPA did not start on port {port}")

    yield f"http://127.0.0.1:{port}"
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)


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


# ---------------------------------------------------------------------------
# Group K — Group-based privilege (Phase 4 core)
# ---------------------------------------------------------------------------


class TestK_GroupPrivilege:
    def test_K1_admin_group_grants_del_rse(self):
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"]) is True

    def test_K2_user_group_denies_del_rse(self):
        assert _q("alice", "del_rse", groups=["/rucio/users"]) is False

    def test_K3_no_groups_denies_privileged_action(self):
        assert _q("alice", "del_rse", groups=[]) is False

    def test_K4_atlas_production_is_admin(self):
        assert _q("prod", "add_rse", groups=["/atlas/production"], rse="CERN_DATADISK") is True

    def test_K5_atlas_users_is_not_admin(self):
        assert _q("alice", "add_rse", groups=["/atlas/users"], rse="CERN_DATADISK") is False

    def test_K6_multiple_groups_any_admin_grants_privilege(self):
        assert _q("alice", "del_rse", groups=["/rucio/users", "/rucio/admins"]) is True

    def test_K7_domain_rules_still_block_admin_groups(self):
        """S3→S3 denied even with admin group — domain checks run first."""
        assert (
            _q(
                "adminuser",
                "add_rule",
                groups=["/rucio/admins"],
                account="adminuser",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="s3",
                dst_protocol="s3",
            )
            is False
        )

    def test_K8_approve_rule_requires_admin_group(self):
        assert _q("alice", "approve_rule", groups=["/rucio/users"]) is False
        assert _q("adminuser", "approve_rule", groups=["/rucio/admins"]) is True


# ---------------------------------------------------------------------------
# Group L — User group self-service actions
# ---------------------------------------------------------------------------


class TestL_UserGroupActions:
    def test_L1_user_can_add_own_unlocked_rule(self):
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

    def test_L2_user_denied_locked_rule(self):
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

    def test_L3_user_denied_rule_for_other_account(self):
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

    def test_L4_user_can_add_did_to_own_scope(self):
        assert (
            _q("alice", "add_did", groups=["/rucio/users"], scope="alice.data", name="file1")
            is True
        )

    def test_L5_user_denied_other_scope(self):
        assert (
            _q("alice", "add_did", groups=["/rucio/users"], scope="bob.data", name="file1") is False
        )

    def test_L6_user_can_del_own_rule(self):
        assert _q("alice", "del_rule", groups=["/rucio/users"], account="alice") is True

    def test_L7_user_denied_del_other_rule(self):
        assert _q("alice", "del_rule", groups=["/rucio/users"], account="bob") is False


# ---------------------------------------------------------------------------
# Group M — Root bootstrap (no OIDC token)
# ---------------------------------------------------------------------------


class TestM_RootBootstrap:
    def test_M1_root_allowed_del_rse(self):
        assert _root("del_rse") is True

    def test_M2_root_allowed_add_rse_valid_name(self):
        assert _root("add_rse", rse="CERN_DATADISK") is True

    def test_M3_root_allowed_unknown_action(self):
        assert _root("some_unknown_action") is True

    def test_M4_root_blocked_by_domain_rules(self):
        assert (
            _root(
                "add_rule",
                account="root",
                locked=False,
                rse_expression="CERN_DATADISK",
                source_protocol="s3",
                dst_protocol="s3",
            )
            is False
        )

    def test_M5_non_root_empty_groups_denied_privileged(self):
        assert _q("alice", "del_rse", groups=[]) is False


# ---------------------------------------------------------------------------
# Group N — Group policy bundle override (runtime)
# ---------------------------------------------------------------------------


class TestN_GroupPolicyBundle:
    def test_N1_custom_group_granted_after_bundle_push(self, opa_server):
        _put(
            opa_server,
            "vo/group_policy",
            {
                "/cms/production": "admin",
                "/rucio/users": "user",
            },
        )
        assert _q("cmsuser", "del_rse", groups=["/cms/production"]) is True

    def test_N2_removed_group_loses_privilege(self, opa_server):
        _put(
            opa_server,
            "vo/group_policy",
            {
                "/atlas/production": "admin",
            },
        )
        assert _q("adminuser", "del_rse", groups=["/rucio/admins"]) is False

    def test_N3_remaining_group_still_privileged(self, opa_server):
        assert _q("prod", "del_rse", groups=["/atlas/production"]) is True

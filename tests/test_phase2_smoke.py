"""
Phase 2 — smoke test against the full Rucio + OPA + PostgreSQL stack.

Unlike test_phase2_e2e.py (which queries OPA directly, bypassing Rucio
entirely) and test_phase2_opa.py (fully mocked HTTP), this file exercises
real Rucio REST endpoints over HTTP: authentication, request routing,
schema validation, and — critically — that Rucio's policy-package hook
actually calls out to OPA end-to-end.

    test_phase2_opa.py    -> unit: input construction, fail-closed
    test_phase2_e2e.py    -> policy content, via OPA directly
    this file              -> wiring: Rucio API -> policy package -> OPA

stack_urls, root_token, rucio_call, and rucio_opa_container_logs are shared
fixtures/helpers defined in conftest.py — see there for details.

Requires a running stack:
    cd phase2-opa/deploy
    docker compose --profile full up -d
    RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
        pytest tests/test_phase2_smoke.py -v

Skips automatically if the stack isn't reachable.
"""

import pytest

from conftest import rucio_call as _rucio_call
from conftest import rucio_opa_container_logs as _rucio_opa_container_logs

# ---------------------------------------------------------------------------
# RSE management — exercises schema validation vs. OPA policy rejection
# ---------------------------------------------------------------------------


class TestRseManagement:
    @pytest.mark.parametrize("rse", ["CERN_DATADISK", "BNL_TAPE", "DESY_SCRATCHDISK"])
    def test_create_valid_rse(self, stack_urls, root_token, rse):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, f"/rses/{rse}", root_token, "POST", {"rse_type": "DISK"})
        assert status in (201, 409)  # 409 if already created by a prior run

    @pytest.mark.parametrize("rse", ["cern_bad", "lowercase_rse"])
    def test_reject_invalid_rse_name_at_schema_level(self, stack_urls, root_token, rse):
        """Rucio's REST schema itself rejects malformed identifiers — before policy runs."""
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, f"/rses/{rse}", root_token, "POST", {"rse_type": "DISK"})
        assert status == 400

    def test_reject_unknown_rse_type_via_policy(self, stack_urls, root_token):
        """Well-formed but disallowed name — rejected by the OPA policy, not the schema."""
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(
            rucio_url, "/rses/CERN_UNKNOWN", root_token, "POST", {"rse_type": "DISK"}
        )
        assert status == 401

    def test_list_rses(self, stack_urls, root_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/rses/", root_token)
        assert status == 200


# ---------------------------------------------------------------------------
# Account + scope management — confirms the API is fully wired, not just RSEs
# ---------------------------------------------------------------------------


class TestAccountAndScope:
    def test_create_account(self, stack_urls, root_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(
            rucio_url,
            "/accounts/testuser",
            root_token,
            "POST",
            {"type": "USER", "email": "test@example.com"},
        )
        assert status in (201, 409)

    def test_get_account(self, stack_urls, root_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/accounts/testuser", root_token)
        assert status == 200

    def test_list_accounts(self, stack_urls, root_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/accounts", root_token)
        assert status == 200

    def test_create_scope(self, stack_urls, root_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/accounts/root/scopes/test", root_token, "POST")
        assert status in (201, 409)

    def test_list_scopes_for_root(self, stack_urls, root_token):
        rucio_url, _ = stack_urls
        status, _ = _rucio_call(rucio_url, "/scopes/root/scopes", root_token)
        assert status == 200


# ---------------------------------------------------------------------------
# Wiring verification — proves Rucio actually calls OPA, not just that OPA
# answers correctly in isolation (that part is test_phase2_e2e.py)
# ---------------------------------------------------------------------------


class TestOpaWiring:
    def test_opa_authz_endpoint_was_hit(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "vo/authz/allow" in logs, "Expected Rucio to have called OPA's authz/allow endpoint."

    def test_opa_policy_was_loaded_via_rest(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "v1/policies/authz" in logs, (
            "Expected the Rego policy to have been PUT to OPA on startup."
        )

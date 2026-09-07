"""
Phase 3 — smoke test against the full Rucio + OPA + PostgreSQL stack.

Same boundary as Phase 2's smoke test — see test_phase2_smoke.py for the
full rationale. Does not duplicate OPA policy-content checks (RSE naming,
account/DID ownership, rule owner self-service, protocol scheme allowlist,
data-driven bundle overrides) — those are covered by test_phase3_e2e.py.

stack_urls, root_token, rucio_call, and rucio_opa_container_logs are shared
fixtures/helpers defined in conftest.py — see there for details.

Requires a running stack:
    cd phase3-opa/deploy
    docker compose --profile full up -d
    RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
        pytest tests/test_phase3_smoke.py -v

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
# Wiring verification — proves Rucio actually calls OPA, not just that OPA
# answers correctly in isolation (that part is test_phase3_e2e.py)
# ---------------------------------------------------------------------------


class TestOpaWiring:
    def test_opa_authz_endpoint_was_hit(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "vo/authz/v2/allow" in logs, (
            "Expected Rucio to have called OPA's authz/v2/allow endpoint."
        )

    def test_opa_policy_was_loaded_via_rest(self):
        logs = _rucio_opa_container_logs()
        if logs is None:
            pytest.skip("docker not available or rucio-opa container not running")
        assert "v1/policies/authz_v2" in logs, (
            "Expected the Rego policy to have been PUT to OPA on startup."
        )

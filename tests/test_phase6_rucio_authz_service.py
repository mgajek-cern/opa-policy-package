"""
Phase 6 — the OIDC → has_permission() → authz-service → OPA path with real
tokens (AUTHZ_MODE=service).

The same contracts as test_phase6_rucio.py, run over the authz-service hop:
permission.py calls authz-service through a generated client
(rucio_authz_client, openapi-generator's python-legacy target — see
services/authorization-service/docs/python39-constraint.md). The hop must not
change any outcome, and must fail closed when authz-service is unreachable.
"""

import pytest

from helpers import USER_USERNAME
from rucio_contracts import (
    BulkScopeOwnershipContract,
    DepPersonaContract,
    PrivilegedPathContract,
    RuleSelfServiceContract,
    ScopeOwnershipContract,
    create_dataset,
)


class TestEntitlementAuthorisation(PrivilegedPathContract):
    """A 5xx here usually means authz-service is unreachable: check
    AUTHZ_SERVICE_URL and that the rucio → authz-service token-exchange grant
    has been run against this Keycloak."""


class TestScopeOwnership(ScopeOwnershipContract):
    pass


class TestBulkScopeOwnership(BulkScopeOwnershipContract):
    pass


class TestRuleSelfService(RuleSelfServiceContract):
    pass


class TestDepPersonaAuthorisationOverAuthzService(DepPersonaContract):
    pass


class TestAuthzServiceUnreachable:
    """A network failure between rucio-server and authz-service is a distinct
    failure mode from the Rego denying, and must fail closed the same way."""

    @pytest.mark.skip(reason="requires container control from the test runner — run manually")
    def test_request_denied_when_authz_service_unreachable(self, user_token):
        # docker stop compose-authz-service-1, run this, docker start it again.
        # permission.py catches any exception from the generated client
        # (ApiException, connection errors) and denies.
        resp = create_dataset(user_token, USER_USERNAME, "outage")
        assert resp.status_code in (401, 403), (
            f"authz-service outage must deny, not silently permit: got {resp.status_code}"
        )

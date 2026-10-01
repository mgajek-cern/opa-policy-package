"""
Phase 5 — the OIDC → has_permission() → OPA path with real tokens.

The two accounts come pre-created in the phase 5 Keycloak realm and are mapped
to same-named Rucio accounts by scripts/init-phase5.sh:

    adminuser      entitlements rucio-admins, atlas-production   acr REFEDS MFA
    randomaccount  entitlements rucio-users,  atlas-users        acr REFEDS MFA

(full URNs of the form urn:example:aai.example.org:group:<name>:role=member).
No group mapper is on the rucio client here, so the token carries entitlement
URNs only. The required_acr deny branch is covered in test_phase5_opa.py.
"""

import pytest

from helpers import ADMIN_USERNAME
from rucio_contracts import RsePrivilegeContract, ScopeOwnershipContract

# Superset of [oidc] expected_scope in configs/rucio/phase5/rucio.cfg, plus
# aud:rucio for expected_audience. Read by the token fixtures in conftest.py.
AUTHZ_SCOPE = "openid offline_access aud:rucio"

pytestmark = pytest.mark.usefixtures("require_rucio")


class TestEntitlementAuthorisation(RsePrivilegeContract):
    """rucio-admins → admin → _is_privileged; rucio-users never reaches it."""


class TestSelfService(ScopeOwnershipContract):
    FOREIGN_SCOPE = ADMIN_USERNAME

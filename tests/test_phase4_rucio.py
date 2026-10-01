"""
Phase 4 — the OIDC → has_permission() → OPA path with real tokens.

The two accounts come pre-created in the phase 4 Keycloak realm and are mapped
to same-named Rucio accounts by scripts/init-phase4.sh:

    adminuser      wlcg.groups /rucio/admins, /atlas/production   acr REFEDS MFA
    randomaccount  wlcg.groups /rucio/users,  /atlas/users        acr REFEDS MFA

data.vo.group_policy maps /rucio/admins and /atlas/production to "admin" and
/rucio/users to "user". Both users carry the same acr, so the required_acr
deny branch is covered against synthetic input in test_phase4_opa.py.
"""

import pytest

from helpers import ADMIN_USERNAME
from rucio_contracts import RsePrivilegeContract, ScopeOwnershipContract

# Superset of [oidc] expected_scope in configs/rucio/phase4/rucio.cfg, plus
# aud:rucio for expected_audience. Read by the token fixtures in conftest.py.
AUTHZ_SCOPE = "openid offline_access aud:rucio"

pytestmark = pytest.mark.usefixtures("require_rucio")


class TestGroupAuthorisation(RsePrivilegeContract):
    """/rucio/admins → admin → _is_privileged; /rucio/users never reaches it."""


class TestSelfService(ScopeOwnershipContract):
    # init-phase4.sh creates the adminuser scope, so the deny is a policy
    # decision and not a missing resource.
    FOREIGN_SCOPE = ADMIN_USERNAME

"""
Phase 4 — scenario tests against a live OPA server.

Privilege comes from wlcg.groups paths. `make test-opa` exports OPA_URL, so
the suite runs against the testbed's own OPA; every fixture that writes to its
data bundle restores what was there.

To run against the checked-in Rego instead of the deployed bundle:

    make test-opa PHASE=4 OPA_URL=

which needs the `opa` binary on PATH. Worth doing when a result here
disagrees with test_phase4_rucio.py — the signal that the container's policy
has drifted from the file.
"""

from pathlib import Path

from opa_contracts import (
    AcrContract,
    AddRuleOwnershipContract,
    ClaimPolicyBundleContract,
    OpaPhase,
    PrivilegedRuleActionsContract,
    PrivilegeTierContract,
    RootBootstrapContract,
    RuleOwnershipContract,
    UserActionsContract,
    UserTierReplicaContract,
)
from rucio_opa_v3_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase4" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v3/allow"
CLAIM_POLICY_PATH = "vo/group_policy"


class Phase4(OpaPhase):
    """Group paths as the wlcg-groups mapper emits them (full.path=true)."""

    CLAIM = "groups"
    query = staticmethod(query_opa)

    ADMIN = "/rucio/admins"
    USER = "/rucio/users"
    ATLAS_PROD = "/atlas/production"
    ATLAS_USER = "/atlas/users"
    UNMAPPED = "/some/other"
    CUSTOM_ADMIN = "/cms/production"

    USER_NAME = "alice"
    OTHER_NAME = "bob"
    OWNED_SCOPE = "alice.data"
    FOREIGN_SCOPE = "bob.data"
    FOREIGN_PREFIXED = "alice.dataleak"


class TestGroupPrivilege(Phase4, PrivilegeTierContract):
    pass


class TestAcrConstraint(Phase4, AcrContract):
    pass


class TestUserGroupActions(Phase4, UserActionsContract):
    pass


class TestAddRuleOwnership(Phase4, AddRuleOwnershipContract):
    pass


class TestRuleOwnership(Phase4, RuleOwnershipContract):
    pass


class TestPrivilegedRuleActions(Phase4, PrivilegedRuleActionsContract):
    pass


class TestAddReplicasPrivilegeLevels(Phase4, UserTierReplicaContract):
    pass


class TestRootBootstrap(Phase4, RootBootstrapContract):
    pass


class TestGroupPolicyBundle(Phase4, ClaimPolicyBundleContract):
    pass

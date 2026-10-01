"""
Phase 5 — scenario tests against a live OPA server.

Same scenarios as phase 4, with privilege from URN entitlements instead of
wlcg.groups paths — only `entitlements` reaches OPA in this phase. `make
test-opa` exports OPA_URL, so the suite runs against the testbed's own OPA;
every fixture that writes to its data bundle restores what was there.

To run against the checked-in Rego instead of the deployed bundle:

    make test-opa PHASE=5 OPA_URL=

which needs the `opa` binary on PATH.
"""

from pathlib import Path

from opa_contracts import (
    AcrContract,
    AddRuleOwnershipContract,
    ClaimPolicyBundleContract,
    EntitlementPhase,
    PrivilegedRuleActionsContract,
    PrivilegeTierContract,
    RootBootstrapContract,
    RuleOwnershipContract,
    UserActionsContract,
    UserTierReplicaContract,
)
from rucio_opa_v4_policy.opa_client import query_opa

REGO_PATH = Path(__file__).parent.parent / "policies" / "rego" / "phase5" / "authz.rego"
OPA_POLICY_PATH = "vo/authz/v4/allow"
CLAIM_POLICY_PATH = "vo/entitlement_policy"


class Phase5(EntitlementPhase):
    query = staticmethod(query_opa)

    USER_NAME = "alice"
    OTHER_NAME = "bob"
    OWNED_SCOPE = "alice.data"
    FOREIGN_SCOPE = "bob.data"
    FOREIGN_PREFIXED = "alice.dataleak"


class TestEntitlementPrivilege(Phase5, PrivilegeTierContract):
    pass


class TestAcrConstraint(Phase5, AcrContract):
    pass


class TestUserEntitlementActions(Phase5, UserActionsContract):
    pass


class TestAddRuleOwnership(Phase5, AddRuleOwnershipContract):
    pass


class TestRuleOwnership(Phase5, RuleOwnershipContract):
    pass


class TestPrivilegedRuleActions(Phase5, PrivilegedRuleActionsContract):
    pass


class TestAddReplicasPrivilegeLevels(Phase5, UserTierReplicaContract):
    pass


class TestRootBootstrap(Phase5, RootBootstrapContract):
    pass


class TestEntitlementPolicyBundle(Phase5, ClaimPolicyBundleContract):
    pass

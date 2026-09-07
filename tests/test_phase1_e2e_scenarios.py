"""
Phase 1 — end-to-end scenario tests

These tests exercise has_permission() as a whole, using named scenarios
that map directly to the flowchart in the README.  Each scenario describes
a user intent, the kwargs Rucio would pass, and the expected outcome.

No live Rucio server is needed — the Rucio DB layer is stubbed.

Protocol-combo scenarios were removed: Rucio core already resolves TPC
feasibility dynamically per-RSE via the third_party_copy_read /
third_party_copy_write protocol capability flags, so the policy package
no longer duplicates that check.
"""

from rucio_no_opa_policy.permission import has_permission

# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------


def _rule_kwargs(
    account,
    *,
    rse_expression="CERN_DATADISK",
    source_rse_expression=None,
    locked=False,
):
    kw = {"account": account, "locked": locked, "rse_expression": rse_expression}
    if source_rse_expression:
        kw["source_rse_expression"] = source_rse_expression
    return kw


# ---------------------------------------------------------------------------
# RSE naming convention (add_rule + add_rse)
# ---------------------------------------------------------------------------


class TestScenario_RseNaming:
    """
    RSE names must follow <SITE>_<TYPE> where TYPE ∈ known storage tiers.
    """

    def test_valid_rse_name_allows_rule(self, regular_account):
        kw = _rule_kwargs(regular_account, rse_expression="BNL_DATADISK")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_lowercase_rse_name_denies_rule(self, regular_account):
        """Lowercase RSE names violate the naming convention."""
        kw = _rule_kwargs(regular_account, rse_expression="bnl_datadisk")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_unknown_rse_type_denies_rule(self, regular_account):
        kw = _rule_kwargs(regular_account, rse_expression="CERN_WHATEVER")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_rse_expression_with_operators_skips_name_check(self, regular_account):
        """Complex RSE expressions (site=X&type=Y) are not bare names — skip validation."""
        kw = _rule_kwargs(regular_account, rse_expression="site=CERN&type=DATADISK")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_root_cannot_register_invalid_rse_name(self, root):
        """RSE naming check applies to add_rse even for root."""
        assert has_permission(root, "add_rse", {"rse": "cern_bad"}) is False

    def test_root_can_register_valid_rse_name(self, root):
        assert has_permission(root, "add_rse", {"rse": "DESY_TAPE"}) is True

    def test_all_known_rse_types_accepted(self, root):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            rse_name = f"CERN_{rse_type}"
            assert has_permission(root, "add_rse", {"rse": rse_name}) is True, (
                f"Expected {rse_name} to be accepted"
            )

    def test_invalid_source_rse_denies_rule(self, regular_account):
        """Source RSE naming is also validated when supplied as a bare name."""
        kw = _rule_kwargs(
            regular_account,
            source_rse_expression="bad_source",
        )
        assert has_permission(regular_account, "add_rule", kw) is False


# ---------------------------------------------------------------------------
# Account / privilege checks (add_rule)
# ---------------------------------------------------------------------------


class TestScenario_AccountChecks:
    """
    Standard Rucio account checks layered on top of domain rules.
    """

    def test_user_creates_own_rule_allowed(self, regular_account):
        """A user can create a rule for their own account."""
        kw = _rule_kwargs(regular_account)
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_user_creates_own_locked_rule_denied(self, regular_account):
        """Locked rules require admin privileges even for self."""
        kw = _rule_kwargs(regular_account, locked=True)
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_user_creates_rule_for_other_denied(self, regular_account, make_account):
        """A non-admin cannot create a rule on behalf of another account."""
        other = make_account("bob")
        kw = _rule_kwargs(other)  # account=bob, issuer=alice
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_root_creates_rule_for_any_account(self, root, make_account):
        """Root can create rules for any account."""
        other = make_account("bob")
        kw = _rule_kwargs(other)
        assert has_permission(root, "add_rule", kw) is True

    def test_admin_creates_rule_for_other_account(self, admin_account, make_account):
        """Admin can create rules for other accounts."""
        other = make_account("carol")
        kw = _rule_kwargs(other)
        assert has_permission(admin_account, "add_rule", kw) is True

    def test_regular_user_denied_add_rse(self, regular_account):
        """Only root/admin can register RSEs."""
        assert has_permission(regular_account, "add_rse", {"rse": "CERN_DATADISK"}) is False

    def test_regular_user_denied_update_rse(self, regular_account):
        """Only root/admin can update RSEs."""
        assert has_permission(regular_account, "update_rse", {"parameters": {}}) is False

    def test_regular_user_denied_unknown_action(self, regular_account):
        """Unrecognised actions fall back to root-or-admin; regular users denied."""
        assert has_permission(regular_account, "del_rse", {}) is False

    def test_root_allowed_unknown_action(self, root):
        """Root is allowed for actions not in the dispatch table."""
        assert has_permission(root, "del_rse", {}) is True


# ---------------------------------------------------------------------------
# RSE rename (update_rse)
# ---------------------------------------------------------------------------


class TestScenario_RseRename:
    def test_root_rename_to_valid_name_allowed(self, root):
        kw = {"parameters": {"rse": "INFN_TAPE"}}
        assert has_permission(root, "update_rse", kw) is True

    def test_root_rename_to_invalid_name_denied(self, root):
        kw = {"parameters": {"rse": "infn_tape"}}
        assert has_permission(root, "update_rse", kw) is False

    def test_root_update_without_rename_always_allowed(self, root):
        kw = {"parameters": {"availability_read": True}}  # no 'rse' key
        assert has_permission(root, "update_rse", kw) is True

    def test_admin_rename_to_valid_name_allowed(self, admin_account):
        kw = {"parameters": {"rse": "NIKHEF_SCRATCHDISK"}}
        assert has_permission(admin_account, "update_rse", kw) is True

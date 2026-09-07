"""
Tests for phase1-no-opa permission.py

Tests the has_permission() dispatch table together with the domain rules,
organized by action. Rucio's DB layer is replaced with monkeypatched stubs
from conftest.py — no live Rucio server is needed.

Previously split across test_phase1_permission.py and
test_phase1_e2e_scenarios.py; merged here since both exercised the same
has_permission() entry point against the same stubbed layer, with
significant overlap once protocol-combo cases were removed.
"""

from rucio_no_opa_policy.permission import has_permission

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _kwargs_add_rule(
    account=None,
    locked=False,
    rse_expression="CERN_DATADISK",
    source_rse_expression=None,
):
    kw = {"locked": locked, "rse_expression": rse_expression}
    if account is not None:
        kw["account"] = account
    if source_rse_expression is not None:
        kw["source_rse_expression"] = source_rse_expression
    return kw


# ---------------------------------------------------------------------------
# add_rule
# ---------------------------------------------------------------------------


class TestAddRule:
    def test_own_unlocked_rule_valid_rse_allowed(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account)
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_own_locked_rule_denied(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account, locked=True)
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_own_rule_invalid_rse_name_denied(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account, rse_expression="cern_bad")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_unknown_rse_type_denied(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account, rse_expression="CERN_WHATEVER")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_rse_expression_with_operators_skips_name_check(self, regular_account):
        """Complex RSE expressions (site=X&type=Y) are not bare names — skip validation."""
        kw = _kwargs_add_rule(account=regular_account, rse_expression="site=CERN&type=DATADISK")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_invalid_source_rse_denied(self, regular_account):
        """Source RSE naming is also validated when supplied as a bare name."""
        kw = _kwargs_add_rule(account=regular_account, source_rse_expression="bad_source")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_rule_for_other_account_denied(self, regular_account, make_account):
        other = make_account("bob")
        kw = _kwargs_add_rule(account=other)
        # alice tries to create a rule for bob — denied
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_root_can_create_rule_for_any_account(self, root, make_account):
        other = make_account("bob")
        kw = _kwargs_add_rule(account=other)
        assert has_permission(root, "add_rule", kw) is True

    def test_root_still_blocked_by_rse_naming(self, root):
        kw = _kwargs_add_rule(rse_expression="bad_name")
        assert has_permission(root, "add_rule", kw) is False

    def test_admin_creates_rule_for_other_account(self, admin_account, make_account):
        other = make_account("carol")
        kw = _kwargs_add_rule(account=other)
        assert has_permission(admin_account, "add_rule", kw) is True


# ---------------------------------------------------------------------------
# add_rse
# ---------------------------------------------------------------------------


class TestAddRse:
    def test_root_valid_name_allowed(self, root):
        assert has_permission(root, "add_rse", {"rse": "BNL_DATADISK"}) is True

    def test_root_invalid_name_denied(self, root):
        assert has_permission(root, "add_rse", {"rse": "bnl_datadisk"}) is False

    def test_root_unknown_type_denied(self, root):
        assert has_permission(root, "add_rse", {"rse": "BNL_UNKNOWN"}) is False

    def test_regular_user_denied_even_valid_name(self, regular_account):
        assert has_permission(regular_account, "add_rse", {"rse": "BNL_DATADISK"}) is False

    def test_admin_valid_name_allowed(self, admin_account):
        assert has_permission(admin_account, "add_rse", {"rse": "DESY_TAPE"}) is True

    def test_all_known_rse_types_accepted(self, root):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            rse_name = f"CERN_{rse_type}"
            assert has_permission(root, "add_rse", {"rse": rse_name}) is True, (
                f"Expected {rse_name} to be accepted"
            )


# ---------------------------------------------------------------------------
# update_rse
# ---------------------------------------------------------------------------


class TestUpdateRse:
    def test_root_no_rename_allowed(self, root):
        assert has_permission(root, "update_rse", {"parameters": {}}) is True

    def test_root_valid_rename_allowed(self, root):
        kw = {"parameters": {"rse": "CERN_TAPE"}}
        assert has_permission(root, "update_rse", kw) is True

    def test_root_invalid_rename_denied(self, root):
        kw = {"parameters": {"rse": "bad_name"}}
        assert has_permission(root, "update_rse", kw) is False

    def test_regular_user_denied(self, regular_account):
        assert has_permission(regular_account, "update_rse", {"parameters": {}}) is False

    def test_admin_rename_to_valid_name_allowed(self, admin_account):
        kw = {"parameters": {"rse": "NIKHEF_SCRATCHDISK"}}
        assert has_permission(admin_account, "update_rse", kw) is True


# ---------------------------------------------------------------------------
# Unknown / unrecognised actions — fall back to root-or-admin
# ---------------------------------------------------------------------------


class TestUnknownAction:
    def test_root_allowed_for_unknown_action(self, root):
        assert has_permission(root, "some_other_action", {}) is True

    def test_regular_user_denied_for_unknown_action(self, regular_account):
        assert has_permission(regular_account, "some_other_action", {}) is False

"""
Tests for phase1-no-opa permission.py

Tests the has_permission() dispatch table together with the domain rules.
Rucio's DB layer is replaced with monkeypatched stubs from conftest.py.
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
    source_protocol=None,
    dst_protocol=None,
):
    kw = {"locked": locked, "rse_expression": rse_expression}
    if account is not None:
        kw["account"] = account
    if source_rse_expression is not None:
        kw["source_rse_expression"] = source_rse_expression
    if source_protocol is not None:
        kw["source_protocol"] = source_protocol
    if dst_protocol is not None:
        kw["dst_protocol"] = dst_protocol
    return kw


# ---------------------------------------------------------------------------
# add_rule — regular account (own rules)
# ---------------------------------------------------------------------------


class TestAddRuleRegularAccount:
    def test_own_unlocked_rule_valid_rse_allowed(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account)
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_own_locked_rule_denied(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account, locked=True)
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_own_rule_invalid_rse_name_denied(self, regular_account):
        kw = _kwargs_add_rule(account=regular_account, rse_expression="cern_bad")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_own_rule_s3_to_s3_denied(self, regular_account):
        kw = _kwargs_add_rule(
            account=regular_account,
            source_protocol="s3",
            dst_protocol="s3",
        )
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_own_rule_webdav_to_s3_denied(self, regular_account):
        """S3 cannot act as TPC destination — FTS streaming required."""
        kw = _kwargs_add_rule(
            account=regular_account,
            source_protocol="webdav",
            dst_protocol="s3",
        )
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_own_rule_s3_to_webdav_allowed(self, regular_account):
        """WebDAV destination can TPC-pull from S3 source."""
        kw = _kwargs_add_rule(
            account=regular_account,
            source_protocol="s3",
            dst_protocol="webdav",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_own_rule_xrdhttp_to_webdav_allowed(self, regular_account):
        """WebDAV destination can TPC-pull from XrdHTTP source."""
        kw = _kwargs_add_rule(
            account=regular_account,
            source_protocol="xrdhttp",
            dst_protocol="webdav",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_rule_for_other_account_denied(self, regular_account, make_account):
        other = make_account("bob")
        kw = _kwargs_add_rule(account=other)
        # alice tries to create a rule for bob — denied
        assert has_permission(regular_account, "add_rule", kw) is False


# ---------------------------------------------------------------------------
# add_rule — root account
# ---------------------------------------------------------------------------


class TestAddRuleRoot:
    def test_root_can_create_rule_for_any_account(self, root, make_account):
        other = make_account("bob")
        kw = _kwargs_add_rule(account=other)
        assert has_permission(root, "add_rule", kw) is True

    def test_root_still_blocked_by_protocol_policy(self, root):
        """Even root must respect the protocol combo rules."""
        kw = _kwargs_add_rule(
            account=root,
            source_protocol="s3",
            dst_protocol="s3",
        )
        assert has_permission(root, "add_rule", kw) is False

    def test_root_still_blocked_by_rse_naming(self, root):
        kw = _kwargs_add_rule(rse_expression="bad_name")
        assert has_permission(root, "add_rule", kw) is False


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


# ---------------------------------------------------------------------------
# Fallback action
# ---------------------------------------------------------------------------


class TestDefaultAction:
    def test_root_allowed_for_unknown_action(self, root):
        assert has_permission(root, "some_other_action", {}) is True

    def test_regular_user_denied_for_unknown_action(self, regular_account):
        assert has_permission(regular_account, "some_other_action", {}) is False

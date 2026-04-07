"""
Phase 1 — end-to-end scenario tests

These tests exercise has_permission() as a whole, using named scenarios
that map directly to the flowchart in the README.  Each scenario describes
a user intent, the kwargs Rucio would pass, and the expected outcome.

No live Rucio server is needed — the Rucio DB layer is stubbed.
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
    source_protocol=None,
    dst_protocol=None,
    locked=False,
):
    kw = {"account": account, "locked": locked, "rse_expression": rse_expression}
    if source_rse_expression:
        kw["source_rse_expression"] = source_rse_expression
    if source_protocol:
        kw["source_protocol"] = source_protocol
    if dst_protocol:
        kw["dst_protocol"] = dst_protocol
    return kw


# ---------------------------------------------------------------------------
# Scenario group A — Protocol combo enforcement (add_rule)
#
# These scenarios map to the "Protocol pair" decision in the flowchart:
#   WebDAV↔WebDAV / WebDAV↔S3 / XrdHTTP↔WebDAV  → allowed (TPC path)
#   S3↔S3                                          → denied  (no TPC)
# ---------------------------------------------------------------------------


class TestScenario_ProtocolCombos:
    """
    User tries to create a replication rule with explicit protocol hints.
    The policy must block invalid TPC combinations regardless of account type.
    """

    def test_A1_webdav_to_webdav_allowed(self, regular_account):
        """WebDAV→WebDAV is a valid TPC path — user's own account, not locked."""
        kw = _rule_kwargs(
            regular_account,
            source_protocol="webdav",
            dst_protocol="webdav",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A2_webdav_to_s3_allowed(self, regular_account):
        """WebDAV→S3 is a valid TPC path."""
        kw = _rule_kwargs(
            regular_account,
            source_protocol="webdav",
            dst_protocol="s3",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A3_s3_to_webdav_allowed(self, regular_account):
        """S3→WebDAV is a valid TPC path."""
        kw = _rule_kwargs(
            regular_account,
            source_protocol="s3",
            dst_protocol="webdav",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A4_xrdhttp_to_webdav_allowed(self, regular_account):
        """XrdHTTP→WebDAV is a valid TPC path."""
        kw = _rule_kwargs(
            regular_account,
            source_protocol="xrdhttp",
            dst_protocol="webdav",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A5_s3_to_s3_denied_for_regular_user(self, regular_account):
        """
        S3→S3 has no TPC support — denied regardless of who requests it.
        This is the primary policy violation from the README flowchart.
        """
        kw = _rule_kwargs(
            regular_account,
            source_protocol="s3",
            dst_protocol="s3",
        )
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_A6_s3_to_s3_denied_even_for_root(self, root):
        """
        Root cannot bypass the protocol policy.
        Domain rules run before privilege checks.
        """
        kw = _rule_kwargs(
            root,
            source_protocol="s3",
            dst_protocol="s3",
        )
        assert has_permission(root, "add_rule", kw) is False

    def test_A7_s3_to_xrdhttp_denied(self, regular_account):
        """S3→XrdHTTP is not a recognised TPC path."""
        kw = _rule_kwargs(
            regular_account,
            source_protocol="s3",
            dst_protocol="xrdhttp",
        )
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_A8_case_insensitive_protocol_names(self, regular_account):
        """Protocol names are normalised to lowercase before checking."""
        kw = _rule_kwargs(
            regular_account,
            source_protocol="WebDAV",
            dst_protocol="S3",
        )
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A9_no_protocol_hints_skips_combo_check(self, regular_account):
        """
        When protocol hints are absent Rucio selects the protocol.
        The policy must not block the rule creation in this case.
        """
        kw = _rule_kwargs(regular_account)  # no source/dst protocol
        assert has_permission(regular_account, "add_rule", kw) is True


# ---------------------------------------------------------------------------
# Scenario group B — RSE naming convention (add_rule + add_rse)
# ---------------------------------------------------------------------------


class TestScenario_RseNaming:
    """
    RSE names must follow <SITE>_<TYPE> where TYPE ∈ known storage tiers.
    """

    def test_B1_valid_rse_name_allows_rule(self, regular_account):
        kw = _rule_kwargs(regular_account, rse_expression="BNL_DATADISK")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_B2_lowercase_rse_name_denies_rule(self, regular_account):
        """Lowercase RSE names violate the naming convention."""
        kw = _rule_kwargs(regular_account, rse_expression="bnl_datadisk")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_B3_unknown_rse_type_denies_rule(self, regular_account):
        kw = _rule_kwargs(regular_account, rse_expression="CERN_WHATEVER")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_B4_rse_expression_with_operators_skips_name_check(self, regular_account):
        """Complex RSE expressions (site=X&type=Y) are not bare names — skip validation."""
        kw = _rule_kwargs(regular_account, rse_expression="site=CERN&type=DATADISK")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_B5_root_cannot_register_invalid_rse_name(self, root):
        """RSE naming check applies to add_rse even for root."""
        assert has_permission(root, "add_rse", {"rse": "cern_bad"}) is False

    def test_B6_root_can_register_valid_rse_name(self, root):
        assert has_permission(root, "add_rse", {"rse": "DESY_TAPE"}) is True

    def test_B7_all_known_rse_types_accepted(self, root):
        for rse_type in ("DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"):
            rse_name = f"CERN_{rse_type}"
            assert has_permission(root, "add_rse", {"rse": rse_name}) is True, (
                f"Expected {rse_name} to be accepted"
            )

    def test_B8_invalid_source_rse_denies_rule(self, regular_account):
        """Source RSE naming is also validated when supplied as a bare name."""
        kw = _rule_kwargs(
            regular_account,
            source_rse_expression="bad_source",
        )
        assert has_permission(regular_account, "add_rule", kw) is False


# ---------------------------------------------------------------------------
# Scenario group C — Account / privilege checks (add_rule)
# ---------------------------------------------------------------------------


class TestScenario_AccountChecks:
    """
    Standard Rucio account checks layered on top of domain rules.
    """

    def test_C1_user_creates_own_rule_allowed(self, regular_account):
        """A user can create a rule for their own account."""
        kw = _rule_kwargs(regular_account)
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_C2_user_creates_own_locked_rule_denied(self, regular_account):
        """Locked rules require admin privileges even for self."""
        kw = _rule_kwargs(regular_account, locked=True)
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_C3_user_creates_rule_for_other_denied(self, regular_account, make_account):
        """A non-admin cannot create a rule on behalf of another account."""
        other = make_account("bob")
        kw = _rule_kwargs(other)  # account=bob, issuer=alice
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_C4_root_creates_rule_for_any_account(self, root, make_account):
        """Root can create rules for any account."""
        other = make_account("bob")
        kw = _rule_kwargs(other)
        assert has_permission(root, "add_rule", kw) is True

    def test_C5_admin_creates_rule_for_other_account(self, admin_account, make_account):
        """Admin can create rules for other accounts."""
        other = make_account("carol")
        kw = _rule_kwargs(other)
        assert has_permission(admin_account, "add_rule", kw) is True

    def test_C6_regular_user_denied_add_rse(self, regular_account):
        """Only root/admin can register RSEs."""
        assert has_permission(regular_account, "add_rse", {"rse": "CERN_DATADISK"}) is False

    def test_C7_regular_user_denied_update_rse(self, regular_account):
        """Only root/admin can update RSEs."""
        assert has_permission(regular_account, "update_rse", {"parameters": {}}) is False

    def test_C8_regular_user_denied_unknown_action(self, regular_account):
        """Unrecognised actions fall back to root-or-admin; regular users denied."""
        assert has_permission(regular_account, "del_rse", {}) is False

    def test_C9_root_allowed_unknown_action(self, root):
        """Root is allowed for actions not in the dispatch table."""
        assert has_permission(root, "del_rse", {}) is True


# ---------------------------------------------------------------------------
# Scenario group D — RSE rename (update_rse)
# ---------------------------------------------------------------------------


class TestScenario_RseRename:
    def test_D1_root_rename_to_valid_name_allowed(self, root):
        kw = {"parameters": {"rse": "INFN_TAPE"}}
        assert has_permission(root, "update_rse", kw) is True

    def test_D2_root_rename_to_invalid_name_denied(self, root):
        kw = {"parameters": {"rse": "infn_tape"}}
        assert has_permission(root, "update_rse", kw) is False

    def test_D3_root_update_without_rename_always_allowed(self, root):
        kw = {"parameters": {"availability_read": True}}  # no 'rse' key
        assert has_permission(root, "update_rse", kw) is True

    def test_D4_admin_rename_to_valid_name_allowed(self, admin_account):
        kw = {"parameters": {"rse": "NIKHEF_SCRATCHDISK"}}
        assert has_permission(admin_account, "update_rse", kw) is True

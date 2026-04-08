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
# Allowed TPC paths (verified with Rucio/FTS maintainers):
#   WebDAV  → WebDAV   ✓  TPC native
#   S3      → WebDAV   ✓  WebDAV pulls from S3
#   XrdHTTP → WebDAV   ✓  WebDAV pulls from XrdHTTP
#   S3      → XrdHTTP  ✓  XrdHTTP pulls from S3 via pre-signed URL
#   XrdHTTP → XrdHTTP  ✓  Native HTTP TPC
#   WebDAV  → S3       ✗  S3 cannot act as TPC destination
#   XrdHTTP → S3       ✗  S3 cannot act as TPC destination
#   S3      → S3       ✗  Neither side supports TPC pull
# ---------------------------------------------------------------------------


class TestScenario_ProtocolCombos:
    """
    User tries to create a replication rule with explicit protocol hints.
    The policy must block invalid TPC combinations regardless of account type.
    """

    def test_A1_webdav_to_webdav_allowed(self, regular_account):
        """WebDAV→WebDAV is a valid TPC path — TPC native."""
        kw = _rule_kwargs(regular_account, source_protocol="webdav", dst_protocol="webdav")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A2_s3_to_webdav_allowed(self, regular_account):
        """S3→WebDAV: WebDAV destination can TPC-pull from S3 source."""
        kw = _rule_kwargs(regular_account, source_protocol="s3", dst_protocol="webdav")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A3_xrdhttp_to_webdav_allowed(self, regular_account):
        """XrdHTTP→WebDAV: WebDAV destination can TPC-pull from XrdHTTP source."""
        kw = _rule_kwargs(regular_account, source_protocol="xrdhttp", dst_protocol="webdav")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A4_s3_to_xrdhttp_allowed(self, regular_account):
        """S3→XrdHTTP: XrdHTTP destination can pull from S3 via pre-signed URL."""
        kw = _rule_kwargs(regular_account, source_protocol="s3", dst_protocol="xrdhttp")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A5_xrdhttp_to_xrdhttp_allowed(self, regular_account):
        """XrdHTTP→XrdHTTP: native HTTP TPC is supported."""
        kw = _rule_kwargs(regular_account, source_protocol="xrdhttp", dst_protocol="xrdhttp")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A6_webdav_to_s3_denied(self, regular_account):
        """WebDAV→S3: S3 cannot act as TPC destination — FTS streaming required."""
        kw = _rule_kwargs(regular_account, source_protocol="webdav", dst_protocol="s3")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_A7_xrdhttp_to_s3_denied(self, regular_account):
        """XrdHTTP→S3: S3 cannot act as TPC destination — FTS streaming required."""
        kw = _rule_kwargs(regular_account, source_protocol="xrdhttp", dst_protocol="s3")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_A8_s3_to_s3_denied_for_regular_user(self, regular_account):
        """S3→S3: neither side supports TPC pull — denied regardless of account."""
        kw = _rule_kwargs(regular_account, source_protocol="s3", dst_protocol="s3")
        assert has_permission(regular_account, "add_rule", kw) is False

    def test_A9_s3_to_s3_denied_even_for_root(self, root):
        """Root cannot bypass the protocol policy — domain rules run first."""
        kw = _rule_kwargs(root, source_protocol="s3", dst_protocol="s3")
        assert has_permission(root, "add_rule", kw) is False

    def test_A10_case_insensitive_protocol_names(self, regular_account):
        """Protocol names are normalised to lowercase before checking."""
        kw = _rule_kwargs(regular_account, source_protocol="S3", dst_protocol="WEBDAV")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A11_case_insensitive_xrdhttp_xrdhttp(self, regular_account):
        """Mixed-case XrdHTTP↔XrdHTTP is also normalised correctly."""
        kw = _rule_kwargs(regular_account, source_protocol="XrdHTTP", dst_protocol="XrdHTTP")
        assert has_permission(regular_account, "add_rule", kw) is True

    def test_A12_no_protocol_hints_skips_combo_check(self, regular_account):
        """When protocol hints are absent Rucio selects the protocol — no block."""
        kw = _rule_kwargs(regular_account)
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

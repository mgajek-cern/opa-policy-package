"""
Unit tests for phase1-no-opa rules.py

These tests cover the pure domain logic — protocol combos and RSE naming —
without touching Rucio internals.  They run without a live Rucio instance.
"""

import pytest

from rucio_no_opa_policy.rules import (
    ALLOWED_PROTOCOL_COMBOS,
    is_protocol_combo_allowed,
    is_rse_name_valid,
    validate_add_rule_kwargs,
)

# ---------------------------------------------------------------------------
# Protocol combo tests
# ---------------------------------------------------------------------------


class TestProtocolCombos:
    @pytest.mark.parametrize(
        "src, dst",
        [
            ("webdav", "webdav"),  # TPC native
            ("WebDAV", "WebDAV"),  # case-insensitive
            ("s3", "webdav"),  # WebDAV pulls from S3
            ("S3", "WebDAV"),  # mixed case
            ("xrdhttp", "webdav"),  # WebDAV pulls from XrdHTTP
            ("XrdHTTP", "WebDAV"),  # mixed case
        ],
    )
    def test_allowed_combos(self, src, dst):
        assert is_protocol_combo_allowed(src, dst) is True

    @pytest.mark.parametrize(
        "src, dst",
        [
            ("s3", "s3"),  # neither side supports TPC pull
            ("webdav", "s3"),  # S3 cannot act as TPC destination
            ("xrdhttp", "s3"),  # S3 cannot act as TPC destination
            ("s3", "xrdhttp"),  # FTS or gateway required
            ("xrdhttp", "xrdhttp"),  # not a supported TPC path
            ("ftp", "webdav"),  # unknown protocol
            ("", "webdav"),  # empty source
        ],
    )
    def test_blocked_combos(self, src, dst):
        assert is_protocol_combo_allowed(src, dst) is False

    def test_s3_webdav_asymmetric(self):
        """S3→WebDAV is allowed (WebDAV pulls); WebDAV→S3 is not (S3 cannot TPC-receive)."""
        assert ("s3", "webdav") in ALLOWED_PROTOCOL_COMBOS
        assert ("webdav", "s3") not in ALLOWED_PROTOCOL_COMBOS
        assert ("s3", "s3") not in ALLOWED_PROTOCOL_COMBOS


# ---------------------------------------------------------------------------
# RSE naming tests
# ---------------------------------------------------------------------------


class TestRseNaming:
    @pytest.mark.parametrize(
        "name",
        [
            "CERN_DATADISK",
            "BNL_SCRATCHDISK",
            "DESY_TAPE",
            "INFN_USERDISK",
            "NIKHEF_LOCALGROUPDISK",
            "SITE01_DATADISK",  # digits in site part
        ],
    )
    def test_valid_names(self, name):
        assert is_rse_name_valid(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "cern_datadisk",  # lowercase — invalid
            "CERNDATADISK",  # no underscore
            "CERN_UNKNOWN",  # unknown type
            "CERN_DATADISK_EXTRA",  # too many underscores → multi-part → type check fails
            "",  # empty
            "CERN_",  # empty type
            "_DATADISK",  # empty site
            "CERN DATADISK",  # space
        ],
    )
    def test_invalid_names(self, name):
        assert is_rse_name_valid(name) is False


# ---------------------------------------------------------------------------
# validate_add_rule_kwargs tests
# ---------------------------------------------------------------------------


class TestValidateAddRuleKwargs:
    def test_bare_valid_rse_no_protocols(self):
        kwargs = {"rse_expression": "CERN_DATADISK"}
        assert validate_add_rule_kwargs(kwargs) is None

    def test_bare_valid_rse_valid_protocol_combo(self):
        kwargs = {
            "rse_expression": "CERN_DATADISK",
            "source_protocol": "s3",
            "dst_protocol": "webdav",
        }
        assert validate_add_rule_kwargs(kwargs) is None

    def test_bare_valid_rse_invalid_protocol_combo_s3_s3(self):
        kwargs = {
            "rse_expression": "CERN_DATADISK",
            "source_protocol": "s3",
            "dst_protocol": "s3",
        }
        error = validate_add_rule_kwargs(kwargs)
        assert error is not None
        assert "S3→S3" in error or "not allowed" in error

    def test_bare_valid_rse_invalid_protocol_combo_webdav_s3(self):
        """webdav→s3 denied: S3 cannot act as TPC destination."""
        kwargs = {
            "rse_expression": "CERN_DATADISK",
            "source_protocol": "webdav",
            "dst_protocol": "s3",
        }
        error = validate_add_rule_kwargs(kwargs)
        assert error is not None
        assert "not allowed" in error

    def test_bare_invalid_rse_name(self):
        kwargs = {"rse_expression": "cern_datadisk"}
        error = validate_add_rule_kwargs(kwargs)
        assert error is not None
        assert "naming convention" in error

    def test_expression_skips_rse_validation(self):
        # Complex expressions like "site=CERN" must not be validated as RSE names
        kwargs = {"rse_expression": "site=CERN&type=DATADISK"}
        assert validate_add_rule_kwargs(kwargs) is None

    def test_source_rse_expression_validated(self):
        kwargs = {
            "rse_expression": "CERN_DATADISK",
            "source_rse_expression": "bad_name",  # lowercase → invalid
        }
        error = validate_add_rule_kwargs(kwargs)
        assert error is not None
        assert "Source RSE" in error

    def test_no_protocols_supplied_skips_combo_check(self):
        # When no protocol hints are given the combo check must be skipped
        kwargs = {"rse_expression": "BNL_TAPE"}
        assert validate_add_rule_kwargs(kwargs) is None

    def test_only_one_protocol_supplied_skips_combo_check(self):
        # Combo check requires BOTH src and dst to be present
        kwargs = {
            "rse_expression": "BNL_TAPE",
            "source_protocol": "s3",
            # dst_protocol absent
        }
        assert validate_add_rule_kwargs(kwargs) is None

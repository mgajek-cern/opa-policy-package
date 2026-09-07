"""
Unit tests for phase1-no-opa rules.py

These tests cover the pure domain logic — RSE naming — without touching
Rucio internals. They run without a live Rucio instance.

Protocol-combo enforcement was removed from the policy package: Rucio
core already resolves TPC feasibility dynamically per-RSE via the
third_party_copy_read / third_party_copy_write protocol capability flags
(see lib/rucio/core/rse.py, lib/rucio/core/transfer.py), so a hardcoded
combo table in the policy package was a stale, duplicate source of truth.
"""

import pytest

from rucio_no_opa_policy.rules import (
    is_rse_name_valid,
    validate_add_rule_kwargs,
)

# RSE naming tests


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


# validate_add_rule_kwargs tests


class TestValidateAddRuleKwargs:
    def test_valid_bare_rse_name(self):
        kwargs = {"rse_expression": "CERN_DATADISK"}
        assert validate_add_rule_kwargs(kwargs) is None

    def test_invalid_bare_rse_name(self):
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

    def test_valid_source_and_destination(self):
        kwargs = {
            "rse_expression": "CERN_DATADISK",
            "source_rse_expression": "BNL_TAPE",
        }
        assert validate_add_rule_kwargs(kwargs) is None

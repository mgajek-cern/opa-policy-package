# Licensed under the Apache License, Version 2.0
"""
Protocol and RSE naming rules for the policy package.

Kept in a dedicated module so the logic can be unit-tested
without a running Rucio instance.

RSE naming convention:
    Pattern:  <SITE>_<TYPE>
    Examples: CERN_DATADISK, BNL_SCRATCHDISK
    Rules:
        - All uppercase ASCII letters, digits and underscores only
        - Must contain exactly one underscore separating site and type
        - Type must be one of the known storage tiers
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_RSE_TYPES: frozenset[str] = frozenset(
    {
        "DATADISK",
        "SCRATCHDISK",
        "LOCALGROUPDISK",
        "TAPE",
        "USERDISK",
    }
)

# <SITE>_<TYPE>  — site: uppercase alphanumeric, type: known tier
_RSE_NAME_RE = re.compile(r"^[A-Z0-9]+_[A-Z0-9]+$")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def is_rse_name_valid(rse_name: str) -> bool:
    """Return True if *rse_name* follows the naming convention.

    Convention: ``<SITE>_<TYPE>`` where TYPE is one of :data:`KNOWN_RSE_TYPES`.
    """
    if not _RSE_NAME_RE.match(rse_name):
        return False
    _, _, rse_type = rse_name.partition("_")
    return rse_type in KNOWN_RSE_TYPES


def validate_add_rule_kwargs(kwargs: dict) -> Optional[str]:
    """Check add_rule kwargs for RSE naming constraints.

    Returns an error message string if validation fails, None if allowed.
    This is called by :func:`perm_add_rule` in permission.py.

    kwargs keys consulted:
        - ``source_rse_expression``  (str, optional)
        - ``rse_expression``         (str, required – destination)
    """
    rse_expression: str = kwargs.get("rse_expression", "")
    src_expression: str = kwargs.get("source_rse_expression", "") or ""

    # RSE expression may contain selectors like "site=CERN"; only validate
    # bare RSE names (no operators).
    if (
        rse_expression
        and _is_bare_rse_name(rse_expression)
        and not is_rse_name_valid(rse_expression)
    ):
        return f"RSE name '{rse_expression}' does not follow naming convention"

    if (
        src_expression
        and _is_bare_rse_name(src_expression)
        and not is_rse_name_valid(src_expression)
    ):
        return f"Source RSE name '{src_expression}' does not follow naming convention"

    return None  # all checks passed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_bare_rse_name(expr: str) -> bool:
    """True if *expr* looks like a plain RSE name rather than an expression."""
    return bool(expr) and "=" not in expr and "&" not in expr and "|" not in expr

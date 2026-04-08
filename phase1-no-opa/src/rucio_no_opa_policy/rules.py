# Licensed under the Apache License, Version 2.0
"""
Protocol and RSE naming rules for the policy package.

Kept in a dedicated module so the logic can be unit-tested
without a running Rucio instance.

Allowed TPC transfer paths (Phase 1 scope):
    WebDAV  → WebDAV   ✓  TPC native (StoRM/dCache/XrdHTTP)
    S3      → WebDAV   ✓  WebDAV destination can TPC-pull from S3 source
    XrdHTTP → WebDAV   ✓  WebDAV destination can TPC-pull from XrdHTTP source
    S3      → XrdHTTP  ✓  XrdHTTP destination can pull from S3 via pre-signed URL
    XrdHTTP → XrdHTTP  ✓  Native HTTP TPC supported
    WebDAV  → S3       ✗  S3 cannot act as TPC destination — FTS streaming required
    XrdHTTP → S3       ✗  S3 cannot act as TPC destination — FTS streaming required
    S3      → S3       ✗  Neither side supports TPC pull

See Transfer Scenarios Overview for the full matrix verified with Rucio/FTS maintainers.

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

ALLOWED_PROTOCOL_COMBOS: frozenset[tuple[str, str]] = frozenset(
    {
        ("webdav", "webdav"),  # TPC native (StoRM/dCache/XrdHTTP)
        ("s3", "webdav"),  # WebDAV destination can TPC-pull from S3 source
        ("xrdhttp", "webdav"),  # WebDAV destination can TPC-pull from XrdHTTP source
        ("s3", "xrdhttp"),  # XrdHTTP destination can pull from S3 via pre-signed URL
        ("xrdhttp", "xrdhttp"),  # Native HTTP TPC supported
        # ("webdav", "s3") and ("xrdhttp", "s3") excluded:
        # S3 cannot act as a TPC destination; requires FTS streaming.
    }
)

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


def is_protocol_combo_allowed(src_protocol: str, dst_protocol: str) -> bool:
    """Return True if the src→dst protocol pair is permitted for TPC transfers.

    Args:
        src_protocol: lowercase protocol name of the source RSE (e.g. "webdav")
        dst_protocol: lowercase protocol name of the destination RSE
    """
    return (src_protocol.lower(), dst_protocol.lower()) in ALLOWED_PROTOCOL_COMBOS


def is_rse_name_valid(rse_name: str) -> bool:
    """Return True if *rse_name* follows the naming convention.

    Convention: ``<SITE>_<TYPE>`` where TYPE is one of :data:`KNOWN_RSE_TYPES`.
    """
    if not _RSE_NAME_RE.match(rse_name):
        return False
    _, _, rse_type = rse_name.partition("_")
    return rse_type in KNOWN_RSE_TYPES


def validate_add_rule_kwargs(kwargs: dict) -> Optional[str]:
    """Check add_rule kwargs for protocol and RSE naming constraints.

    Returns an error message string if validation fails, None if allowed.
    This is called by :func:`perm_add_rule` in permission.py.

    kwargs keys consulted:
        - ``source_rse_expression``  (str, optional)
        - ``rse_expression``         (str, required – destination)
        - ``source_protocol``        (str, optional) — protocol hint
        - ``dst_protocol``           (str, optional) — protocol hint
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

    # Protocol combo check — only if both sides are explicitly supplied
    src_proto: str = kwargs.get("source_protocol", "") or ""
    dst_proto: str = kwargs.get("dst_protocol", "") or ""
    if src_proto and dst_proto and not is_protocol_combo_allowed(src_proto, dst_proto):
        return (
            f"Protocol combination {src_proto.upper()}→{dst_proto.upper()} "
            "is not allowed (no TPC support)"
        )

    return None  # all checks passed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_bare_rse_name(expr: str) -> bool:
    """True if *expr* looks like a plain RSE name rather than an expression."""
    return bool(expr) and "=" not in expr and "&" not in expr and "|" not in expr

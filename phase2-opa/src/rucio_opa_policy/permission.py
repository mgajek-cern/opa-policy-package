# Licensed under the Apache License, Version 2.0
"""
Phase 2 permission module — OPA acts as the Policy Decision Point.

Every call to has_permission() constructs a structured input document
and forwards it to a running OPA server.  The Rego policies (../rego/)
encode all authorisation logic; this module is intentionally thin.

Input document shape sent to OPA:
    {
        "issuer":   "<account external name>",
        "action":   "<rucio action string>",
        "is_root":  <bool>,
        "is_admin": <bool>,   # set when Rucio has already resolved it
        "kwargs":   { ... }   // filtered subset of kwargs — no DB sessions
    }
"""

from typing import TYPE_CHECKING, Any

from rucio.core.account import has_account_attribute

from rucio_opa_policy.opa_client import query_opa

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from sqlalchemy.orm import Session


# ---------------------------------------------------------------------------
# Entry point called by Rucio
# ---------------------------------------------------------------------------


def has_permission(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    """Forward the permission decision to OPA."""
    input_doc = _build_input(issuer, action, kwargs, session=session)
    return query_opa(input_doc)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_input(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> dict[str, Any]:
    """
    Construct the OPA input document.

    SQLAlchemy session objects and other non-serialisable values are
    stripped from kwargs before forwarding.
    """
    is_root = issuer.external == "root"
    # Resolve the admin flag cheaply here so Rego does not need a DB call.
    # We only look it up when the issuer is not already root.
    is_admin = False
    if not is_root:
        try:
            is_admin = bool(has_account_attribute(account=issuer, key="admin", session=session))
        except Exception:  # noqa: BLE001 — never let a DB error block the build
            is_admin = False

    return {
        "issuer": issuer.external,
        "action": action,
        "is_root": is_root,
        "is_admin": is_admin,
        "kwargs": _serialisable_kwargs(kwargs),
    }


_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        # add_rule / del_rule / update_rule
        "account",
        "locked",
        "rse_expression",
        "source_rse_expression",
        "source_protocol",
        "dst_protocol",
        # add_rse / update_rse / del_rse / rse attributes
        "rse",
        "parameters",
        "rse_id",
        # DIDs
        "scope",
        "name",
        "dids",
        "attachments",
    }
)


def _serialisable_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-serialisable subset of kwargs."""
    result: dict[str, Any] = {}
    for key in _PASSTHROUGH_KEYS:
        if key in kwargs:
            val = kwargs[key]
            # Convert Rucio InternalAccount / InternalScope to their string form
            if hasattr(val, "external"):
                val = val.external
            result[key] = val
    return result

# Licensed under the Apache License, Version 2.0
"""
Phase 1 permission module — Rucio acts as the Policy Decision Point.

All decisions are made in Python without calling an external service.
The main additions over the generic permission module are:

  - perm_add_rule   : enforces protocol-combo and RSE naming rules
  - perm_add_rse    : enforces RSE naming convention on creation
  - perm_update_rse : enforces RSE naming convention on rename

All other actions fall back to the generic Rucio behaviour
(root or account with 'admin' attribute).
"""

from typing import TYPE_CHECKING, Any

from rucio.core.account import has_account_attribute

from rucio_no_opa_policy.rules import is_rse_name_valid, validate_add_rule_kwargs

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
    """Dispatch table: map action name → permission function."""
    dispatch: dict[str, Any] = {
        "add_rule": perm_add_rule,
        "add_rse": perm_add_rse,
        "update_rse": perm_update_rse,
    }
    handler = dispatch.get(action, _perm_default)
    return handler(issuer=issuer, kwargs=kwargs, session=session)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_root(issuer: "InternalAccount") -> bool:
    return issuer.external == "root"


def _is_admin(issuer: "InternalAccount", *, session: "Optional[Session]") -> bool:
    return has_account_attribute(account=issuer, key="admin", session=session)


def _perm_default(
    issuer: "InternalAccount",
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    """Generic fallback: only root or admin accounts are allowed."""
    return _is_root(issuer) or _is_admin(issuer, session=session)


# ---------------------------------------------------------------------------
# Action-specific permission functions
# ---------------------------------------------------------------------------


def perm_add_rule(
    issuer: "InternalAccount",
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    """
    Allow a replication rule to be added.

    Standard Rucio checks:
      - The issuer can create rules for their own account (non-locked).
      - Root and admins can always create rules.

    Additions:
      - The destination RSE (rse_expression) must follow the naming convention
        when it is a bare RSE name.
      - The source→destination protocol combination must be in the allowed set.
    """
    # --- Domain checks first (fast, no DB) ---
    error = validate_add_rule_kwargs(kwargs)
    if error:
        return False  # rule would violate protocol / naming policy

    # --- Standard Rucio account checks ---
    if kwargs.get("account") == issuer and not kwargs.get("locked"):
        return True
    return _is_root(issuer) or _is_admin(issuer, session=session)


def perm_add_rse(
    issuer: "InternalAccount",
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    """
    Allow an RSE to be registered.

    Root / admin required AND the RSE name must follow the naming convention.
    """
    if not (_is_root(issuer) or _is_admin(issuer, session=session)):
        return False
    rse_name: str = kwargs.get("rse", "")
    return is_rse_name_valid(rse_name)


def perm_update_rse(
    issuer: "InternalAccount",
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    """
    Allow an RSE to be updated.

    If the update includes a rename, the new name must pass validation.
    """
    if not (_is_root(issuer) or _is_admin(issuer, session=session)):
        return False
    # kwargs may contain 'parameters' dict with a 'rse' key for rename
    parameters: dict = kwargs.get("parameters", {}) or {}
    new_name: str = parameters.get("rse", "")
    if new_name:
        return is_rse_name_valid(new_name)
    return True

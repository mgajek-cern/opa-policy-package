# Licensed under the Apache License, Version 2.0
"""
Phase 3 permission module — OPA as PDP, broader action coverage.

Extends Phase 2 with additional kwargs passed through to OPA for:
  - attach_dids_to_dids  (rucio-it-tools gap)
  - add_did / add_dids   (scope-owner parity with Phase 2 DID actions)
  - del_rule / update_rule (rule-owner self-service)
  - add_protocol / del_protocol / update_protocol (scheme allowlist)

Input document shape (unchanged from Phase 2):
    {
        "issuer":   "<account external name>",
        "action":   "<rucio action string>",
        "is_root":  <bool>,
        "is_admin": <bool>,
        "kwargs":   { ... }
    }
"""

from typing import TYPE_CHECKING, Any

from rucio.core.account import has_account_attribute

from rucio_opa_v2_policy.opa_client import query_opa

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from sqlalchemy.orm import Session


def has_permission(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    """Forward every permission decision to OPA."""
    input_doc = _build_input(issuer, action, kwargs, session=session)
    return query_opa(input_doc)


def _build_input(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> dict[str, Any]:
    is_root = issuer.external == "root"
    is_admin = False
    if not is_root:
        try:
            is_admin = bool(has_account_attribute(account=issuer, key="admin", session=session))
        except Exception:  # noqa: BLE001
            is_admin = False

    return {
        "issuer": issuer.external,
        "action": action,
        "is_root": is_root,
        "is_admin": is_admin,
        "kwargs": _serialisable_kwargs(kwargs),
    }


# Extended relative to Phase 2 — new keys for newly delegated actions.
_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        # add_rule / del_rule / update_rule / move_rule
        "account",
        "locked",
        "rse_expression",
        "source_rse_expression",
        "source_protocol",
        "dst_protocol",
        "rule_id",  # del_rule / update_rule — identifies the rule owner
        # add_rse / update_rse / del_rse / rse attributes
        "rse",
        "parameters",
        "rse_id",
        # add_protocol / del_protocol / update_protocol
        "scheme",  # protocol scheme (davs, s3, https, root, xrdhttp)
        "hostname",
        "data",  # update_protocol payload
        # DIDs — all DID actions including attach_dids_to_dids
        "scope",
        "name",
        "dids",
        "attachments",  # attach_dids_to_dids bulk payload
    }
)


def _serialisable_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-serialisable subset of kwargs."""
    result: dict[str, Any] = {}
    for key in _PASSTHROUGH_KEYS:
        if key in kwargs:
            val = kwargs[key]
            if hasattr(val, "external"):
                val = val.external
            result[key] = val
    return result

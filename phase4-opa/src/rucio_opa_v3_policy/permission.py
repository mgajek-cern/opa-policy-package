# Licensed under the Apache License, Version 2.0
"""
Phase 4 permission module — OIDC token-native OPA authorisation.

Key difference from Phase 3:
  - No is_root / is_admin pre-resolution from the Rucio DB.
  - wlcg.groups from the validated JWT are extracted and forwarded to OPA
    as token.groups.
  - OPA evaluates group membership against data.vo.group_policy in the bundle.

Input document shape:
    {
        "issuer":  "<account external name>",
        "action":  "<rucio action string>",
        "token":   { "groups": ["/rucio/admins", "/atlas/users"] },
        "kwargs":  { ... }
    }

For accounts that authenticated via userpass (e.g. the bootstrap root account),
token.groups will be an empty list. The Rego rule
  _is_privileged if { input.issuer == "root" }
handles this unconditionally so the server can start.
"""

import logging
import os
from typing import TYPE_CHECKING, Any

from rucio_opa_v3_policy.opa_client import query_opa

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

_DEBUG_INPUT = os.environ.get("RUCIO_OPA_DEBUG_INPUT", "").strip() in ("1", "true", "True")


def has_permission(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> bool:
    input_doc = _build_input(issuer, action, kwargs)
    if _DEBUG_INPUT:
        log.warning("OPA input for action=%s: %s", action, input_doc)
    return query_opa(input_doc)


def _build_input(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    return {
        "issuer": issuer.external,
        "action": action,
        "token": {"groups": _extract_groups()},
        "kwargs": _serialisable_kwargs(kwargs),
    }


def _extract_groups() -> list[str]:
    """
    Extract wlcg.groups from the account's OIDC token if present.

    Rucio attaches decoded JWT claims to InternalAccount via oidc_token_info
    after the /auth/oidc flow. Falls back to [] for non-OIDC accounts.
    """
    try:
        from flask import has_request_context, request
    except ImportError:
        if _DEBUG_INPUT:
            log.warning("OPA entitlements: flask not importable")
        return []
    if not has_request_context():
        if _DEBUG_INPUT:
            log.warning("OPA entitlements: no flask request context")
        return []
    claims = request.environ.get("token_claims") or {}
    value = claims.get("wlcg.groups", [])
    wlcg_groups = value.split() if isinstance(value, str) else list(value)
    if _DEBUG_INPUT:
        log.warning(
            "OPA entitlements: claim_keys=%s wlcg.groups=%s",
            sorted(claims),
            wlcg_groups,
        )
    return wlcg_groups


_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        "account",
        "locked",
        "rse_expression",
        "source_rse_expression",
        "rule_id",
        "rse",
        "parameters",
        "rse_id",
        "scheme",
        "hostname",
        "data",
        "scope",
        "name",
        "dids",
        "attachments",
    }
)


def _serialisable_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in _PASSTHROUGH_KEYS:
        if key in kwargs:
            val = kwargs[key]
            if hasattr(val, "external"):
                val = val.external
            result[key] = val
    return result

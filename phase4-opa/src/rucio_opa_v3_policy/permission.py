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

from typing import TYPE_CHECKING, Any

from rucio_opa_v3_policy.opa_client import query_opa

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
    input_doc = _build_input(issuer, action, kwargs)
    return query_opa(input_doc)


def _build_input(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    return {
        "issuer": issuer.external,
        "action": action,
        "token": {"groups": _extract_groups(issuer)},
        "kwargs": _serialisable_kwargs(kwargs),
    }


def _extract_groups(issuer: "InternalAccount") -> list[str]:
    """
    Extract wlcg.groups from the account's OIDC token if present.

    Rucio attaches decoded JWT claims to InternalAccount via oidc_token_info
    after the /auth/oidc flow. Falls back to [] for non-OIDC accounts.
    """
    try:
        token_info: dict = getattr(issuer, "oidc_token_info", None) or {}
        return list(token_info.get("wlcg.groups", []))
    except Exception:  # noqa: BLE001
        return []


_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        "account",
        "locked",
        "rse_expression",
        "source_rse_expression",
        "source_protocol",
        "dst_protocol",
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

# Licensed under the Apache License, Version 2.0
"""
Phase 5 permission module — OIDC token-native OPA authorisation via URN entitlements.

Key difference from Phase 4:
  - No is_root / is_admin pre-resolution from the Rucio DB.
  - Claims from the validated JWT are forwarded to OPA under `token`; the URN
    entitlements arrive as token.entitlements.
  - OPA evaluates entitlement membership against data.vo.entitlement_policy
    in the bundle.

Input document shape:
    {
        "issuer":  "<account external name>",
        "action":  "<rucio action string>",
        "token":   {
            "entitlements": ["urn:example:aai.example.org:group:rucio-admins:role=member"],
            "acr":          "https://refeds.org/profile/mfa",
            "aud":          "rucio",
            "iss":          "http://keycloak:8080/realms/rucio",
            "sub":          "..."
        },
        "kwargs":  { ... }
    }

Scalar claims appear only when the token carries them; the list claims are
always present so a Rego clause iterating them is safe. For accounts that
authenticated via userpass (e.g. the bootstrap root account) every list is
empty and no scalar is set. The Rego rule
  _is_privileged if { input.issuer == "root" }
handles this unconditionally so the server can start.
"""

import logging
import os
from typing import TYPE_CHECKING, Any

from rucio_opa_v4_policy.opa_client import query_opa

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

_DEBUG_INPUT = os.environ.get("RUCIO_OPA_DEBUG_INPUT", "").strip() in ("1", "true", "True")

# Claims forwarded to OPA, as <input.token key>: <claim name>.
_LIST_CLAIMS: dict[str, str] = {
    "entitlements": "entitlements",
}

_SCALAR_CLAIMS: tuple[str, ...] = ("acr", "aud", "iss", "sub")


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
        "token": _token_claims(),
        "kwargs": _serialisable_kwargs(kwargs),
    }


def _request_claims() -> dict[str, Any]:
    """
    The decoded JWT payload for the current request.

    Populated by the patched REST layer (see patches/rucio/). Returns {}
    outside a request context, which unit tests rely on.
    """
    try:
        from flask import has_request_context, request
    except ImportError:
        if _DEBUG_INPUT:
            log.warning("OPA token claims: flask not importable")
        return {}
    if not has_request_context():
        if _DEBUG_INPUT:
            log.warning("OPA token claims: no flask request context")
        return {}
    return request.environ.get("token_claims") or {}


def _as_list(value: Any) -> list[str]:
    """
    Normalise a claim that may be a list or a space-separated string.

    IdPs emit single- and multi-valued claims either way; list("urn:...")
    would silently produce a list of characters.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    return list(value)


def _token_claims() -> dict[str, Any]:
    claims = _request_claims()

    token: dict[str, Any] = {
        key: _as_list(claims.get(claim)) for key, claim in _LIST_CLAIMS.items()
    }
    for key in _SCALAR_CLAIMS:
        if key in claims:
            token[key] = claims[key]

    if _DEBUG_INPUT:
        log.warning("OPA token claims: claim_keys=%s forwarded=%s", sorted(claims), token)

    return token


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

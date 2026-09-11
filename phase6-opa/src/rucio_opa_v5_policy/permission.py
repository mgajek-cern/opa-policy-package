# Licensed under the Apache License, Version 2.0
"""
Phase 6 permission module — OIDC token-native OPA authorisation via URN entitlements.

Key difference from Phase 5:
  - No is_root / is_admin pre-resolution from the Rucio DB.
  - URN entitlements from the validated JWT are extracted and forwarded to
    OPA as token.entitlements.
  - OPA evaluates entitlement membership against data.vo.entitlement_policy
    in the bundle.

 Input document shape:
     {
         "issuer":  "<account external name>",
         "action":  "<rucio action string>",
        "token":   { "entitlements": [
                        "urn:example:aai.example.org:group:rucio-admins:role=member"
                     ] },
         "kwargs":  { ... }
     }

For accounts that authenticated via userpass (e.g. the bootstrap root account),
token.entitlements will be an empty list. The Rego rule
   _is_privileged if { input.issuer == "root" }
 handles this unconditionally so the server can start.
"""

import logging
import os
from typing import TYPE_CHECKING, Any

from rucio_opa_v5_policy.opa_client import query_opa

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

# Set RUCIO_OPA_DEBUG_INPUT=1 in the rucio-server environment to log every
# OPA input document at WARNING level — useful for diagnosing "Access
# denied" errors where it's unclear which kwarg Rego is missing. Off by
# default since it can be noisy / verbose in production.
_DEBUG_INPUT = os.environ.get("RUCIO_OPA_DEBUG_INPUT", "").strip() in ("1", "true", "True")
log.warning("rucio_opa_v5_policy.permission loaded from %s", __file__)


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
        "token": {"entitlements": _extract_entitlements()},
        "kwargs": _serialisable_kwargs(kwargs),
    }


def _extract_entitlements() -> list[str]:
    """
    Read the entitlements claim from the current request.

    Populated by the patched REST layer (see patches/rucio/). Returns []
    outside a request context, which unit tests rely on.
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
    value = claims.get("entitlements", [])
    entitlements = [value] if isinstance(value, str) else list(value)
    if _DEBUG_INPUT:
        log.warning(
            "OPA entitlements: claim_keys=%s entitlements=%s",
            sorted(claims),
            entitlements,
        )
    return entitlements


_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        "account",
        "locked",
        "rse_expression",
        "source_rse_expression",
        "rule_id",
        "rse",
        "parameters",
        "parameter",
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

# Keys under which a nested protocol/parameter dict might carry `scheme` —
# Rucio's add_protocol API passes the scheme/hostname/port/prefix bundled
# into one dict (matching add_protocol(rse_id, parameter, *, session) in
# core), not as flat kwargs. Check these, in order, for a top-level
# `scheme` substitute so existing Rego (`input.kwargs.scheme`) keeps working.
_NESTED_SCHEME_CONTAINERS = ("parameter", "parameters", "data")


def _serialisable_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in _PASSTHROUGH_KEYS:
        if key in kwargs:
            val = kwargs[key]
            if hasattr(val, "external"):
                val = val.external
            result[key] = val

    if "scheme" not in result:
        for container_key in _NESTED_SCHEME_CONTAINERS:
            nested = kwargs.get(container_key)
            if isinstance(nested, dict) and "scheme" in nested:
                result["scheme"] = nested["scheme"]
                break

    return result

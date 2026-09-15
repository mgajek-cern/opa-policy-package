# Licensed under the Apache License, Version 2.0
"""
Phase 6 permission module — OIDC token-native OPA authorisation via URN entitlements.

Key difference from Phase 5:
  - Same entitlement model; the Rego adds an RSE-name allowlist for the
    testbed RSEs and the transfer path is exercised end to end.

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
        "kwargs":  { ..., "owned_scopes": ["alice", "alice.data"] }
    }

Scalar claims appear only when the token carries them; the list claims are
always present so a Rego clause iterating them is safe. For accounts that
authenticated via userpass (e.g. the bootstrap root account) every list is
empty and no scalar is set. The Rego rule
  _is_privileged if { input.issuer == "root" }
handles this unconditionally so the server can start.

`kwargs.owned_scopes` is the subset of the scopes named in this request that
the issuer actually owns, resolved against the `scopes` table. No token claim
can carry it — the IdP has no concept of a Rucio scope — so Python fetches
the fact and the Rego decides on it.
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
# OPA input document at WARNING level
_DEBUG_INPUT = os.environ.get("RUCIO_OPA_DEBUG_INPUT", "").strip() in ("1", "true", "True")

# Claims forwarded to OPA, as <input.token key>: <claim name>.
_LIST_CLAIMS: dict[str, str] = {
    "entitlements": "entitlements",
}

_SCALAR_CLAIMS: tuple[str, ...] = ("acr", "aud", "iss", "sub")

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

_SCOPE_CONTAINERS: tuple[str, ...] = ("dids", "attachments")


def has_permission(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> "PermissionResult":  # noqa: F821
    from rucio.core.permission import PermissionResult

    # 1. Isolate input generation to catch underlying implementation bugs cleanly
    try:
        input_doc = _build_input(issuer, action, kwargs, session)
    except Exception:
        # Catch genuine implementation faults (e.g., typos inside nested code helpers)
        # without allowing a partial failure to proceed down an untrusted path.
        log.exception(
            "OPA engineering fault: Input payload generation failed for action=%s", action
        )
        return PermissionResult(False, "Internal authorization failure: Payload construction error")

    if _DEBUG_INPUT:
        log.warning("OPA input for action=%s: %s", action, input_doc)

    # 2. Execute network-bound policy assessment inside a dedicated safety block
    try:
        # Refactor query_opa downstream to return an object or tuple containing
        # both a boolean decision status and a contextual reason string from Rego
        opa_response = query_opa(input_doc)

        # Fallback handling assuming query_opa returns a boolean or structured object
        if isinstance(opa_response, bool):
            allowed = opa_response
            reason = "" if allowed else "Access denied by OPA policy validation"
        else:
            allowed = getattr(opa_response, "allowed", False)
            reason = getattr(opa_response, "reason", "Access denied by OPA policy validation")

        return PermissionResult(allowed, reason)

    except Exception as network_err:
        # 3. Fail-Closed cleanly on infrastructure outages (Network Down, OPA Container Dead)
        log.critical(
            "OPA connection infrastructure failure for action=%s: %s",
            action,
            str(network_err),
            exc_info=True,
        )
        return PermissionResult(False, "Authorization engine unreachable (System Degraded)")


def _build_input(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    session: "Optional[Session]" = None,
) -> dict[str, Any]:
    serialisable = _serialisable_kwargs(kwargs)
    serialisable["owned_scopes"] = _owned_scopes(issuer, kwargs, session)
    return {
        "issuer": issuer.external,
        "action": action,
        "token": _token_claims(),
        "kwargs": serialisable,
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


# Scope ownership


def _scopes_in(issuer: "InternalAccount", kwargs: dict[str, Any]) -> list[Any]:
    """Every distinct scope named by this request, as InternalScope."""
    from rucio.common.types import InternalScope

    found = []
    candidates = []

    if "scope" in kwargs:
        candidates.append(kwargs["scope"])
    for container in _SCOPE_CONTAINERS:
        for entry in kwargs.get(container) or []:
            if isinstance(entry, dict) and "scope" in entry:
                candidates.append(entry["scope"])

    for value in candidates:
        if value is None:
            continue
        scope = value if hasattr(value, "internal") else InternalScope(value, vo=issuer.vo)
        if scope not in found:
            found.append(scope)

    return found


def _owned_scopes(
    issuer: "InternalAccount",
    kwargs: dict[str, Any],
    session: "Optional[Session]" = None,
) -> list[str]:
    """
    The subset of this request's scopes that the issuer owns.
    """
    scopes = (
        _scopes_in(issuer, kwargs)
        if "scope" in kwargs or any(k in kwargs for k in _SCOPE_CONTAINERS)
        else []
    )
    if not scopes or session is None:
        return []

    try:
        from rucio.core.scope import is_scope_owner
    except ImportError:
        if _DEBUG_INPUT:
            log.warning("OPA owned_scopes: rucio.core.scope not importable")
        return []

    owned = [
        scope.external
        for scope in scopes
        if is_scope_owner(scope=scope, account=issuer, session=session)
    ]

    if _DEBUG_INPUT:
        log.warning(
            "OPA owned_scopes: checked=%s owned=%s",
            [s.external for s in scopes],
            owned,
        )

    return owned


def _externalise(value: Any) -> Any:
    """
    Recursively replace InternalScope/InternalAccount with their external
    string form.

    `dids` and `attachments` are lists of dicts whose `scope` the gateway has
    already converted to InternalScope, so unwrapping only the top level
    leaves objects json.dumps cannot serialise — query_opa would fail closed
    on every bulk DID action, including for root.
    """
    if hasattr(value, "external"):
        return value.external
    if isinstance(value, dict):
        return {k: _externalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_externalise(v) for v in value]
    return value


def _serialisable_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in _PASSTHROUGH_KEYS:
        if key in kwargs:
            result[key] = _externalise(kwargs[key])

    if "scheme" not in result:
        for container_key in _NESTED_SCHEME_CONTAINERS:
            nested = kwargs.get(container_key)
            if isinstance(nested, dict) and "scheme" in nested:
                result["scheme"] = nested["scheme"]
                break

    return result

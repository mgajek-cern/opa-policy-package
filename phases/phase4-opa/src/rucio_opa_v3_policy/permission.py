# Licensed under the Apache License, Version 2.0
"""
Phase 4 permission module — OIDC token-native OPA authorisation.

Key difference from Phase 3:
  - No is_root / is_admin pre-resolution from the Rucio DB.
  - Claims from the validated JWT are forwarded to OPA under `token`;
    wlcg.groups arrives as token.groups.
  - OPA evaluates group membership against data.vo.group_policy in the bundle.

Input document shape:
    {
        "issuer":  "<account external name>",
        "action":  "<rucio action string>",
        "token":   {
            "groups":       ["/rucio/admins", "/atlas/users"],
            "acr":          "https://refeds.org/profile/mfa",
            "aud":          "rucio",
            "iss":          "http://keycloak:8080/realms/rucio",
            "sub":          "..."
        },
        "kwargs":  { ...,
                     "owned_scopes": ["alice", "alice.data"],
                     "rule_owner":   "alice",
                     "rule_scope":   "alice.data" }
    }

Scalar claims appear only when the token carries them; the list claims are
always present so a Rego clause iterating them is safe. For accounts that
authenticated via userpass (e.g. the bootstrap root account) every list is
empty and no scalar is set. The Rego rule
  _is_privileged if { input.issuer == "root" }
handles this unconditionally so the server can start.

Two families of fact are resolved in Python rather than read off a claim,
because no IdP has authoritative knowledge of them (design-003, design-004):

  - `kwargs.owned_scopes` — the subset of the scopes named in this request
    that the issuer owns, from the `scopes` table.
  - `kwargs.rule_owner` / `kwargs.rule_scope` — for rule-id-keyed actions,
    the rule's owning account and the scope of the DID it targets, from the
    `rules` table. Absent when the rule cannot be resolved, which makes the
    Rego comparison undefined and denies.
"""

import logging
import os
from typing import TYPE_CHECKING, Any

from rucio_opa_v3_policy.opa_client import query_opa

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from rucio.core.permission import PermissionResult
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

_DEBUG_INPUT = os.environ.get("RUCIO_OPA_DEBUG_INPUT", "").strip() in ("1", "true", "True")

# Claims forwarded to OPA, as <input.token key>: <claim name>.
_LIST_CLAIMS: dict[str, str] = {
    "groups": "wlcg.groups",
}

_SCALAR_CLAIMS: tuple[str, ...] = ("acr", "aud", "iss", "sub")

_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        "account",
        "locked",
        "rse_expression",
        "source_rse_expression",
        "rule_id",
        "options",
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

# kwargs keys holding a single scope, and keys holding a list of dicts that
# each carry one. `rule_scope` is not a gateway kwarg — it is resolved by
# _rule_facts() and merged in before ownership is computed, so that one
# lookup covers it alongside everything else.
_SCOPE_KEYS: tuple[str, ...] = ("scope", "rule_scope")
_SCOPE_CONTAINERS: tuple[str, ...] = ("dids", "attachments")

# Actions whose kwargs identify a rule by id and nothing else. The owning
# account lives on the `rules` row, not in kwargs, so it has to be fetched.
_RULE_ID_ACTIONS: frozenset[str] = frozenset({"del_rule", "update_rule"})


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
    rule_facts = _rule_facts(action, kwargs, session)

    serialisable = _serialisable_kwargs(kwargs)
    serialisable.update(rule_facts)

    # _scopes_in() reads the raw kwargs, which carry no rule_scope — merge the
    # resolved facts in first so a rule's target scope is resolved by the same
    # single is_scope_owner() pass as everything else in the request.
    serialisable["owned_scopes"] = _owned_scopes(issuer, {**kwargs, **rule_facts}, session)

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


# Rule ownership


def _rule_facts(
    action: str,
    kwargs: dict[str, Any],
    session: "Optional[Session]" = None,
) -> dict[str, str]:
    """
    The rule's owning account and target scope, for rule-id-keyed actions.

    Returns {} when the facts cannot be established — a missing rule, an
    unusable id, or no session. The Rego comparison is then undefined and
    the action denies, which is the intended failure direction.
    """
    if action not in _RULE_ID_ACTIONS or session is None:
        return {}

    rule_id = kwargs.get("rule_id")
    if not rule_id:
        return {}

    try:
        from rucio.common.exception import RuleNotFound
        from rucio.core.rule import get_rule
    except ImportError:
        if _DEBUG_INPUT:
            log.warning("OPA rule_facts: rucio.core.rule not importable")
        return {}

    try:
        row = get_rule(rule_id, session=session)
    except RuleNotFound:
        # An ordinary outcome, not a fault: nothing to own, so nothing to
        # compare against.
        if _DEBUG_INPUT:
            log.warning("OPA rule_facts: rule %s not found", rule_id)
        return {}
    except Exception:
        # A fault. Still denies, but never silently — otherwise a transient
        # DB error is indistinguishable from "you don't own this rule".
        log.exception("OPA rule_facts: could not resolve rule %s", rule_id)
        return {}

    facts = {
        "rule_owner": row["account"].external,
        "rule_scope": row["scope"].external,
    }

    if _DEBUG_INPUT:
        log.warning("OPA rule_facts: rule=%s facts=%s", rule_id, facts)

    return facts


# Scope ownership


def _scopes_in(issuer: "InternalAccount", kwargs: dict[str, Any]) -> list[Any]:
    """Every distinct scope named by this request, as InternalScope."""
    from rucio.common.types import InternalScope

    found = []
    candidates = []

    for key in _SCOPE_KEYS:
        if key in kwargs:
            candidates.append(kwargs[key])
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
    named = any(k in kwargs for k in _SCOPE_KEYS) or any(k in kwargs for k in _SCOPE_CONTAINERS)
    scopes = _scopes_in(issuer, kwargs) if named else []
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
    return result

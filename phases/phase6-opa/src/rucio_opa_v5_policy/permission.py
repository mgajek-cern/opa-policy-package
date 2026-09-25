# Licensed under the Apache License, Version 2.0
"""
Unified permission module — dispatches has_permission() to one of two
authorization backends, selected by AUTHZ_MODE:

    AUTHZ_MODE=direct   (default) — query OPA directly (former phase 6 path)
    AUTHZ_MODE=service              — call the Authorization Service over
                                       HTTP via the generated client
                                       (former phase 7 path)

Both modes decide against the same authz.rego content
(policies/rego/phase6/authz.rego); only how has_permission() reaches a
decision differs. See
docs/design/design-007-fold-phase6-phase7-authz-mode.md.

Two families of fact are resolved in Python rather than read off a
claim, because no IdP has authoritative knowledge of them
(design-003, design-004):

  - the subset of scopes named in this request that the issuer owns,
    from the `scopes` table.
  - for rule-id-keyed actions, the rule's owning account and the scope
    of the DID it targets, from the `rules` table. Absent when the
    rule cannot be resolved, which denies in both modes.

AUTHZ_MODE=service scope: OIDC-authenticated accounts only.
get_token_for_account_operation requires an existing OIDC subject
token on file; x509/userpass/SSH/GSS accounts have none and get an
explicit deny, not a silent fallback. Deliberate, not an oversight.
AUTHZ_MODE=direct has no such restriction — it forwards whatever
token claims the request already carries (empty for non-OIDC
accounts, root included, which authz.rego handles unconditionally via
`_is_privileged if { input.issuer == "root" }`).
"""

import logging
import os
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing import Optional

    from rucio.common.types import InternalAccount
    from rucio.core.permission import PermissionResult
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

AUTHZ_MODE = os.environ.get("AUTHZ_MODE", "direct").strip().lower()

# Set RUCIO_OPA_DEBUG_INPUT=1 in the rucio-server environment to log every
# outbound request/input document at WARNING level, in either mode.
_DEBUG_INPUT = os.environ.get("RUCIO_OPA_DEBUG_INPUT", "").strip() in ("1", "true", "True")

# Actions whose kwargs identify a rule by id and nothing else. The owning
# account lives on the `rules` row, not in kwargs, so it has to be fetched.
# Shared by both modes.
_RULE_ID_ACTIONS: frozenset[str] = frozenset({"del_rule", "update_rule"})


def has_permission(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> "PermissionResult":
    if AUTHZ_MODE == "service":
        return _has_permission_service(issuer, action, kwargs, session=session)
    return _has_permission_direct(issuer, action, kwargs, session=session)


# ════════════════════════════════════════════════════════════════
# Shared helpers — identical under both modes
# ════════════════════════════════════════════════════════════════


def _externalise(value: Any) -> Any:
    if hasattr(value, "external"):
        return value.external
    if isinstance(value, Enum):
        # Rucio passes DIDType/RSEType members inside dids[] and parameter
        # dicts. json.dumps cannot serialise them, and an unserialisable
        # input document fails the whole decision closed.
        return value.value
    if isinstance(value, dict):
        return {k: _externalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_externalise(v) for v in value]
    return value


def _rule_facts(
    action: str,
    kwargs: dict[str, Any],
    session: "Optional[Session]" = None,
) -> dict[str, str]:
    """
    The rule's owning account and target scope, for rule-id-keyed actions.

    Returns {} when the facts cannot be established — a missing rule, an
    unusable id, or no session. Both modes' downstream comparison is then
    undefined and denies, which is the intended failure direction.
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
            log.warning("authz: rucio.core.rule not importable")
        return {}

    try:
        row = get_rule(rule_id, session=session)
    except RuleNotFound:
        # An ordinary outcome, not a fault: nothing to own, so nothing to
        # compare against.
        if _DEBUG_INPUT:
            log.warning("authz: rule %s not found", rule_id)
        return {}
    except Exception:
        # A fault. Still denies, but never silently — otherwise a transient
        # DB error is indistinguishable from "you don't own this rule".
        log.exception("authz: could not resolve rule %s", rule_id)
        return {}

    facts = {
        "rule_owner": row["account"].external,
        "rule_scope": row["scope"].external,
    }

    if _DEBUG_INPUT:
        log.warning("authz: rule=%s facts=%s", rule_id, facts)

    return facts


# ════════════════════════════════════════════════════════════════
# AUTHZ_MODE=direct — query OPA directly (former phase 6 path)
# ════════════════════════════════════════════════════════════════

from rucio_opa_v5_policy.opa_client import query_opa  # noqa: E402

# Claims forwarded to OPA, as <input.token key>: <claim name>.
_LIST_CLAIMS: dict[str, str] = {"entitlements": "entitlements"}
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
# into one dict, not as flat kwargs. Checked, in order, for a top-level
# `scheme` substitute so `input.kwargs.scheme` in the Rego keeps working.
_NESTED_SCHEME_CONTAINERS = ("parameter", "parameters", "data")

# kwargs keys holding a single scope, and keys holding a list of dicts that
# each carry one. `rule_scope` is not a gateway kwarg — it is resolved by
# _rule_facts() and merged in before ownership is computed.
_SCOPE_KEYS: tuple[str, ...] = ("scope", "rule_scope")
_SCOPE_CONTAINERS: tuple[str, ...] = ("dids", "attachments")


def _has_permission_direct(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> "PermissionResult":
    from rucio.core.permission import PermissionResult

    try:
        input_doc = _build_input(issuer, action, kwargs, session)
    except Exception:
        log.exception("OPA: input payload generation failed for action=%s", action)
        return PermissionResult(False, "Internal authorization failure: payload construction error")

    if _DEBUG_INPUT:
        log.warning("OPA input for action=%s: %s", action, input_doc)

    try:
        opa_response = query_opa(input_doc)
        if isinstance(opa_response, bool):
            allowed = opa_response
            reason = "" if allowed else "Access denied by OPA policy validation"
        else:
            allowed = getattr(opa_response, "allowed", False)
            reason = getattr(opa_response, "reason", "Access denied by OPA policy validation")
        return PermissionResult(allowed, reason)
    except Exception as network_err:
        log.critical(
            "OPA connection infrastructure failure for action=%s: %s",
            action,
            str(network_err),
            exc_info=True,
        )
        return PermissionResult(False, "Authorization engine unreachable (system degraded)")


def _build_input(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    session: "Optional[Session]" = None,
) -> dict[str, Any]:
    rule_facts = _rule_facts(action, kwargs, session)

    serialisable = _serialisable_kwargs(kwargs)
    serialisable.update(rule_facts)

    # _scopes_in() reads the raw kwargs, which carry no rule_scope — merge
    # the resolved facts in first so a rule's target scope is resolved by
    # the same single is_scope_owner() pass as everything else.
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
            log.warning("authz: flask not importable")
        return {}
    if not has_request_context():
        if _DEBUG_INPUT:
            log.warning("authz: no flask request context")
        return {}
    return request.environ.get("token_claims") or {}


def _as_list(value: Any) -> list[str]:
    """Normalise a claim that may be a list or a space-separated string."""
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
        log.warning("authz: claim_keys=%s forwarded=%s", sorted(claims), token)
    return token


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
    """The subset of this request's scopes that the issuer owns."""
    named = any(k in kwargs for k in _SCOPE_KEYS) or any(k in kwargs for k in _SCOPE_CONTAINERS)
    scopes = _scopes_in(issuer, kwargs) if named else []
    if not scopes or session is None:
        return []

    try:
        from rucio.core.scope import is_scope_owner
    except ImportError:
        if _DEBUG_INPUT:
            log.warning("authz: rucio.core.scope not importable")
        return []

    owned = [
        scope.external
        for scope in scopes
        if is_scope_owner(scope=scope, account=issuer, session=session)
    ]
    if _DEBUG_INPUT:
        log.warning("authz: checked=%s owned=%s", [s.external for s in scopes], owned)
    return owned


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


# ════════════════════════════════════════════════════════════════
# AUTHZ_MODE=service — call authz-service via generated client
# (former phase 7 path). Imports are top-level: rucio_authz_client
# ships in this same package now, so it's always installed
# regardless of which mode is active.
# ════════════════════════════════════════════════════════════════

from rucio_authz_client.api.dids_api import DidsApi  # noqa: E402
from rucio_authz_client.api.privileged_api import PrivilegedApi  # noqa: E402
from rucio_authz_client.api.protocols_api import ProtocolsApi  # noqa: E402
from rucio_authz_client.api.replicas_api import ReplicasApi  # noqa: E402
from rucio_authz_client.api.rses_api import RsesApi  # noqa: E402
from rucio_authz_client.api.rules_api import RulesApi  # noqa: E402
from rucio_authz_client.api_client import ApiClient  # noqa: E402
from rucio_authz_client.configuration import Configuration  # noqa: E402
from rucio_authz_client.exceptions import ApiException  # noqa: E402
from rucio_authz_client.models.context import Context  # noqa: E402
from rucio_authz_client.models.did import Did  # noqa: E402
from rucio_authz_client.models.did_attach_request import DidAttachRequest  # noqa: E402
from rucio_authz_client.models.did_create_request import DidCreateRequest  # noqa: E402
from rucio_authz_client.models.did_detach_request import DidDetachRequest  # noqa: E402
from rucio_authz_client.models.privileged_operation_request import (  # noqa: E402
    PrivilegedOperationRequest,
)
from rucio_authz_client.models.protocol import Protocol  # noqa: E402
from rucio_authz_client.models.protocol_create_request import ProtocolCreateRequest  # noqa: E402
from rucio_authz_client.models.protocol_delete_request import ProtocolDeleteRequest  # noqa: E402
from rucio_authz_client.models.protocol_update_request import ProtocolUpdateRequest  # noqa: E402
from rucio_authz_client.models.replica_delete_request import ReplicaDeleteRequest  # noqa: E402
from rucio_authz_client.models.replica_register_request import ReplicaRegisterRequest  # noqa: E402
from rucio_authz_client.models.rse import Rse  # noqa: E402
from rucio_authz_client.models.rse_attribute_delete_request import (  # noqa: E402
    RseAttributeDeleteRequest,
)
from rucio_authz_client.models.rse_attribute_delete_request_attribute import (  # noqa: E402
    RseAttributeDeleteRequestAttribute,
)
from rucio_authz_client.models.rse_attribute_set_request import (  # noqa: E402
    RseAttributeSetRequest,
)
from rucio_authz_client.models.rse_attribute_set_request_attribute import (  # noqa: E402
    RseAttributeSetRequestAttribute,
)
from rucio_authz_client.models.rse_create_request import RseCreateRequest  # noqa: E402
from rucio_authz_client.models.rse_delete_request import RseDeleteRequest  # noqa: E402
from rucio_authz_client.models.rse_update_request import RseUpdateRequest  # noqa: E402
from rucio_authz_client.models.rse_update_request_changes import (  # noqa: E402
    RseUpdateRequestChanges,
)
from rucio_authz_client.models.rule import Rule  # noqa: E402
from rucio_authz_client.models.rule_create_request import RuleCreateRequest  # noqa: E402
from rucio_authz_client.models.rule_create_request_rule import RuleCreateRequestRule  # noqa: E402
from rucio_authz_client.models.rule_delete_request import RuleDeleteRequest  # noqa: E402
from rucio_authz_client.models.rule_update_request import RuleUpdateRequest  # noqa: E402
from rucio_authz_client.models.rule_update_request_changes import (  # noqa: E402
    RuleUpdateRequestChanges,
)
from rucio_authz_client.models.scope import Scope as _ClientScope  # noqa: E402
from rucio_authz_client.models.subject import Subject  # noqa: E402

AUTHZ_SERVICE_URL = os.environ.get("AUTHZ_SERVICE_URL", "http://localhost:8000")
AUTHZ_AUDIENCE = os.environ.get("AUTHZ_OIDC_AUDIENCE", "authz-service")
AUTHZ_SCOPE = os.environ.get("AUTHZ_REQUIRED_SCOPE", "pep:rucio")
_VO = os.environ.get("AUTHZ_VO", "def")


def _client(token: str) -> ApiClient:
    config = Configuration()
    config.host = AUTHZ_SERVICE_URL
    config.access_token = token
    return ApiClient(config)


def _has_permission_service(
    issuer: "InternalAccount",
    action: str,
    kwargs: dict[str, Any],
    *,
    session: "Optional[Session]" = None,
) -> "PermissionResult":
    from rucio.core.permission import PermissionResult

    try:
        token = _authz_token(issuer, session)
    except Exception:
        log.exception("authz-service: could not obtain a scoped token for issuer=%s", issuer)
        return PermissionResult(False, "Authorization engine unreachable (no token)")

    if token is None:
        log.warning("authz-service: no scoped token available for issuer=%s", issuer)
        return PermissionResult(False, "No authz-service token available for this identity")

    try:
        call, body = _build_request(issuer, action, kwargs, session)
    except Exception:
        log.exception("authz-service: request body construction failed for action=%s", action)
        return PermissionResult(False, "Internal authorization failure: payload construction error")

    if _DEBUG_INPUT:
        log.warning("authz-service request for action=%s: %s", action, body)

    try:
        client = _client(token)
        decision = call(client, body)
    except ApiException as exc:
        # 400/401/403/500 are all Problem responses per the contract — the
        # PEP treats every one of them as a deny, not just 403.
        log.warning("authz-service %s -> HTTP %s: %s", action, exc.status, exc.body)
        return PermissionResult(False, f"authz-service returned {exc.status} for action={action}")
    except Exception as exc:
        log.critical("authz-service call failed for action=%s: %s", action, exc, exc_info=True)
        return PermissionResult(False, "Authorization engine unreachable (system degraded)")

    allowed = bool(decision.decision)
    return PermissionResult(allowed, "" if allowed else "Access denied by authz-service")


def _authz_token(issuer: "InternalAccount", session: "Optional[Session]") -> "Optional[str]":
    from rucio.core.oidc import get_token_for_account_operation

    token_dict = get_token_for_account_operation(
        issuer,
        req_audience=AUTHZ_AUDIENCE,
        req_scope=AUTHZ_SCOPE,
        admin=False,
        session=session,
    )
    return token_dict["token"] if token_dict else None


def _subject(issuer: "InternalAccount") -> Subject:
    kind = "rucio_account" if issuer.external == "root" else "oidc_subject"
    return Subject(type=kind, id=issuer.external)


def _context() -> Context:
    return Context(vo=_VO)


def _scope_owner(scope: Any, session: "Optional[Session]") -> str:
    """The scope's real owning account — NOT the requesting issuer."""
    if session is None:
        log.warning("authz-service: no session available to resolve scope owner for %s", scope)
        return str(scope)
    try:
        from rucio.common.types import InternalScope
        from rucio.core.scope import list_scopes_with_account

        internal_scope = scope if hasattr(scope, "internal") else InternalScope(scope, vo=_VO)
        rows = list(list_scopes_with_account(filter_={"scope": internal_scope}, session=session))
        if not rows:
            log.warning("authz-service: scope %s has no owning account", internal_scope)
            return internal_scope.external
        return rows[0]["account"].external
    except Exception:
        log.exception("authz-service: scope owner lookup failed for %s", scope)
        return str(scope)


def _did(scope: Any, name: str, session: "Optional[Session]") -> Did:
    owner = _scope_owner(scope, session)
    scope_name = scope.external if hasattr(scope, "external") else str(scope)
    return Did(scope=_ClientScope(name=scope_name, owner=owner), name=name)


def _b_rule_create(issuer, kwargs, facts, session):
    body = RuleCreateRequest(
        subject=_subject(issuer),
        rule=RuleCreateRequestRule(
            owner=str(kwargs["account"]),
            locked=kwargs["locked"],
            rse_expression=kwargs.get("rse_expression"),
            source_rse_expression=kwargs.get("source_rse_expression"),
            dids=[_did(d["scope"], d["name"], session) for d in kwargs.get("dids", [])],
        ),
        context=_context(),
    )
    return (lambda c, b: RulesApi(c).authorize_rule_create(b)), body


def _b_rule_update(issuer, kwargs, facts, session):
    body = RuleUpdateRequest(
        subject=_subject(issuer),
        rule=Rule(
            id=kwargs["rule_id"],
            owner=facts.get("rule_owner", ""),
            target=_did(facts.get("rule_scope", ""), "", session),
        ),
        changes=RuleUpdateRequestChanges(
            **{
                k: v
                for k, v in (kwargs.get("options") or {}).items()
                if k in ("owner", "lifetime", "rse_expression")
            }
        ),
        context=_context(),
    )
    return (lambda c, b: RulesApi(c).authorize_rule_update(b)), body


def _b_rule_delete(issuer, kwargs, facts, session):
    body = RuleDeleteRequest(
        subject=_subject(issuer),
        rule=Rule(
            id=kwargs["rule_id"],
            owner=facts.get("rule_owner", ""),
            target=_did(facts.get("rule_scope", ""), "", session),
        ),
        context=_context(),
    )
    return (lambda c, b: RulesApi(c).authorize_rule_delete(b)), body


def _b_dids_create(issuer, kwargs, facts, session):
    dids = kwargs.get("dids") or [{"scope": kwargs.get("scope"), "name": kwargs.get("name")}]
    body = DidCreateRequest(
        subject=_subject(issuer),
        dids=[_did(d["scope"], d["name"], session) for d in dids],
        context=_context(),
    )
    return (lambda c, b: DidsApi(c).authorize_did_create(b)), body


def _b_dids_attach(issuer, kwargs, facts, session):
    attachments = kwargs.get("attachments") or [
        {"scope": kwargs.get("scope"), "name": kwargs.get("name"), "dids": []}
    ]
    body = DidAttachRequest(
        subject=_subject(issuer),
        attachments=[
            {
                "parent": _did(a["scope"], a["name"], session),
                "children": [_did(c["scope"], c["name"], session) for c in a.get("dids", [])],
            }
            for a in attachments
        ],
        context=_context(),
    )
    return (lambda c, b: DidsApi(c).authorize_did_attach(b)), body


def _b_dids_detach(issuer, kwargs, facts, session):
    body = DidDetachRequest(
        subject=_subject(issuer),
        parent=_did(kwargs["scope"], kwargs["name"], session),
        children=[],
        context=_context(),
    )
    return (lambda c, b: DidsApi(c).authorize_did_detach(b)), body


def _b_rse_create(issuer, kwargs, facts, session):
    body = RseCreateRequest(
        subject=_subject(issuer), rse=Rse(name=kwargs["rse"]), context=_context()
    )
    return (lambda c, b: RsesApi(c).authorize_rse_create(b)), body


def _b_rse_update(issuer, kwargs, facts, session):
    params = kwargs.get("parameters", {}) or {}
    changes = (
        RseUpdateRequestChanges(name=params["rse"])
        if "rse" in params
        else RseUpdateRequestChanges()
    )
    body = RseUpdateRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs["rse"]),
        changes=changes,
        context=_context(),
    )
    return (lambda c, b: RsesApi(c).authorize_rse_update(b)), body


def _b_rse_delete(issuer, kwargs, facts, session):
    body = RseDeleteRequest(
        subject=_subject(issuer), rse=Rse(name=kwargs["rse"]), context=_context()
    )
    return (lambda c, b: RsesApi(c).authorize_rse_delete(b)), body


def _b_rse_attr_set(issuer, kwargs, facts, session):
    body = RseAttributeSetRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs["rse"]),
        attribute=RseAttributeSetRequestAttribute(key=kwargs["key"]),
        context=_context(),
    )
    return (lambda c, b: RsesApi(c).authorize_rse_attribute_set(b)), body


def _b_rse_attr_delete(issuer, kwargs, facts, session):
    body = RseAttributeDeleteRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs["rse"]),
        attribute=RseAttributeDeleteRequestAttribute(key=kwargs["key"]),
        context=_context(),
    )
    return (lambda c, b: RsesApi(c).authorize_rse_attribute_delete(b)), body


def _b_protocol_create(issuer, kwargs, facts, session):
    body = ProtocolCreateRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs["rse"]),
        protocol=Protocol(scheme=kwargs.get("scheme")),
        context=_context(),
    )
    return (lambda c, b: ProtocolsApi(c).authorize_protocol_create(b)), body


def _b_protocol_update(issuer, kwargs, facts, session):
    body = ProtocolUpdateRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs["rse"]),
        protocol=Protocol(scheme=kwargs.get("scheme")),
        context=_context(),
    )
    return (lambda c, b: ProtocolsApi(c).authorize_protocol_update(b)), body


def _b_protocol_delete(issuer, kwargs, facts, session):
    body = ProtocolDeleteRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs["rse"]),
        protocol=Protocol(scheme=kwargs.get("scheme")),
        context=_context(),
    )
    return (lambda c, b: ProtocolsApi(c).authorize_protocol_delete(b)), body


def _b_replicas_register(issuer, kwargs, facts, session):
    files = kwargs.get("files") or []
    body = ReplicaRegisterRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs.get("rse")),
        files=[_did(f["scope"], f["name"], session) for f in files],
        context=_context(),
    )
    return (lambda c, b: ReplicasApi(c).authorize_replica_register(b)), body


def _b_replicas_delete(issuer, kwargs, facts, session):
    files = kwargs.get("files") or []
    body = ReplicaDeleteRequest(
        subject=_subject(issuer),
        rse=Rse(name=kwargs.get("rse")),
        files=[_did(f["scope"], f["name"], session) for f in files],
        context=_context(),
    )
    return (lambda c, b: ReplicasApi(c).authorize_replica_delete(b)), body


def _b_privileged(issuer, kwargs, facts, session, *, action):
    body = PrivilegedOperationRequest(
        subject=_subject(issuer), operation=action, context=_context()
    )
    return (lambda c, b: PrivilegedApi(c).authorize_privileged_operation(b)), body


_SERVICE_DISPATCH = {
    "add_rule": _b_rule_create,
    "update_rule": _b_rule_update,
    "del_rule": _b_rule_delete,
    "add_did": _b_dids_create,
    "add_dids": _b_dids_create,
    "attach_dids": _b_dids_attach,
    "attach_dids_to_dids": _b_dids_attach,
    "detach_dids": _b_dids_detach,
    "add_rse": _b_rse_create,
    "update_rse": _b_rse_update,
    "del_rse": _b_rse_delete,
    "add_rse_attribute": _b_rse_attr_set,
    "del_rse_attribute": _b_rse_attr_delete,
    "add_protocol": _b_protocol_create,
    "update_protocol": _b_protocol_update,
    "del_protocol": _b_protocol_delete,
    "add_replicas": _b_replicas_register,
    "delete_replicas": _b_replicas_delete,
}


def _build_request(issuer, action, kwargs, session):
    facts = _rule_facts(action, kwargs, session)
    builder = _SERVICE_DISPATCH.get(action)
    if builder is None:
        return _b_privileged(issuer, kwargs, facts, session, action=action)
    return builder(issuer, kwargs, facts, session)

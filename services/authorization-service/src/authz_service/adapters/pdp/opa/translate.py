"""Evaluation <-> OPA translation.

Evaluation -> OPA input reproduces the document phase 7's _build_input()
sent, so the unchanged vo.authz.v6 Rego keeps deciding the same way
(design-006, "The PDP port"). OPA's response -> Outcome is generic and
covers every operation.

kwargs are action-specific, so they land one operation at a time
(design-006, "Migration"). del_rule, add_rule and update_rule are
registered; everything else (dids, rses, protocols, replicas,
privileged-operations) is still parked, and to_opa_input() raises for
any unregistered action rather than guessing a shape that could
silently flip a decision.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from authz_service.core.model import Evaluation, Outcome

# Claims forwarded to OPA, mirroring phase 7's _token_claims() allowlist.
_LIST_CLAIMS = ("entitlements",)
_SCALAR_CLAIMS = ("acr", "aud", "iss", "sub", "jti")


def _token(evaluation: Evaluation) -> dict[str, Any]:
    claims = evaluation.subject.claims
    token: dict[str, Any] = {key: claims[key] for key in _LIST_CLAIMS if key in claims}
    for key in _SCALAR_CLAIMS:
        if key in claims:
            token[key] = claims[key]
    return token


def _kwargs_del_rule(evaluation: Evaluation) -> dict[str, Any]:
    """del_rule (authz.rego): rule_owner alone, or privilege. No scope
    ownership check — that's update_rule's rule, not this one."""
    rule = evaluation.resources[0]
    return {"rule_id": rule.id, "rule_owner": rule.owner}


def _kwargs_add_rule(evaluation: Evaluation) -> dict[str, Any]:
    """add_rule (authz.rego _perm_add_rule): kwargs.account == issuer,
    locked == false, every DID's scope owned — or privilege. Resources
    are the rule's DIDs; account/locked/rse_expression/
    source_rse_expression ride in evaluation.context, since they
    describe the rule being created, not a resource being acted on."""
    subject_id = evaluation.subject.id
    dids = [
        {"scope": resource.attributes.get("scope"), "name": resource.id}
        for resource in evaluation.resources
    ]
    owned_scopes = sorted(
        {
            resource.attributes.get("scope")
            for resource in evaluation.resources
            if resource.owner == subject_id and resource.attributes.get("scope")
        }
    )
    kwargs: dict[str, Any] = {
        "account": evaluation.context.get("account"),
        "locked": evaluation.context.get("locked", False),
        "dids": dids,
        "owned_scopes": owned_scopes,
    }
    rse_expression = evaluation.context.get("rse_expression")
    if rse_expression:
        kwargs["rse_expression"] = rse_expression
    source_rse_expression = evaluation.context.get("source_rse_expression")
    if source_rse_expression:
        kwargs["source_rse_expression"] = source_rse_expression
    return kwargs


def _kwargs_update_rule(evaluation: Evaluation) -> dict[str, Any]:
    """update_rule (authz.rego _perm_update_rule): privilege, or
    (no reassignment requested AND rule_owner == issuer AND rule_scope
    owned). Reassignment is any non-null changes.owner, including
    reassignment to the current owner — options.account is only sent
    when that's the case, matching _rule_reassignment_requested's
    object.get(..., null) != null check."""
    subject_id = evaluation.subject.id
    rule = evaluation.resources[0]
    scope = rule.attributes.get("scope")
    scope_owner = rule.attributes.get("scope_owner")
    owned_scopes = [scope] if scope and scope_owner == subject_id else []

    kwargs: dict[str, Any] = {
        "rule_id": rule.id,
        "rule_owner": rule.owner,
        "rule_scope": scope,
        "owned_scopes": owned_scopes,
    }
    changes = evaluation.context.get("changes") or {}
    if changes.get("owner") is not None:
        kwargs["options"] = {"account": changes["owner"]}
    return kwargs


_KWARGS_BUILDERS: dict[str, Callable[[Evaluation], dict[str, Any]]] = {
    "del_rule": _kwargs_del_rule,
    "add_rule": _kwargs_add_rule,
    "update_rule": _kwargs_update_rule,
}


def to_opa_input(evaluation: Evaluation) -> dict[str, Any]:
    try:
        build_kwargs = _KWARGS_BUILDERS[evaluation.operation]
    except KeyError:
        raise ValueError(
            f"no OPA input mapping registered for action {evaluation.operation!r}"
        ) from None

    return {
        "issuer": evaluation.subject.id,
        "action": evaluation.operation,
        "token": _token(evaluation),
        "kwargs": build_kwargs(evaluation),
    }


def outcome_from_response(status_code: int, body: Any) -> Outcome:
    if status_code >= 500:
        return Outcome.INDETERMINATE
    if not isinstance(body, dict):
        return Outcome.INDETERMINATE
    if "result" not in body:
        return Outcome.NOT_APPLICABLE
    result = body["result"]
    if not isinstance(result, bool):
        return Outcome.INDETERMINATE
    return Outcome.PERMIT if result else Outcome.DENY

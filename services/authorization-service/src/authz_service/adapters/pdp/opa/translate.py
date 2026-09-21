"""Evaluation <-> OPA translation.

Evaluation -> OPA input reproduces the document phase 7's _build_input()
sent, so the unchanged vo.authz.v6 Rego keeps deciding the same way
(design-006, "The PDP port"). OPA's response -> Outcome is generic and
covers every operation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from authz_service.core.model import Evaluation, Outcome, Resource

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


def _owned_scopes(subject_id: str, resources: Iterable[Resource]) -> list[str]:
    """Scopes among the given resources that the subject owns, deduped
    and sorted. Each resource must carry its scope name in
    attributes["scope"]; ownership is resource.owner == subject_id."""
    return sorted(
        {
            resource.attributes.get("scope")
            for resource in resources
            if resource.owner == subject_id and resource.attributes.get("scope")
        }
    )


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
    dids = [
        {"scope": resource.attributes.get("scope"), "name": resource.id}
        for resource in evaluation.resources
    ]
    kwargs: dict[str, Any] = {
        "account": evaluation.context.get("account"),
        "locked": evaluation.context.get("locked", False),
        "dids": dids,
        "owned_scopes": _owned_scopes(evaluation.subject.id, evaluation.resources),
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
    object.get(..., null) != null check.

    Ownership here is scope ownership (attributes["scope_owner"]), not
    resource.owner (which is the rule's owner) — the two can differ, as
    in "randomaccount owns this rule, but the rule targets ddmlab's
    scope." Deliberately not routed through the shared _owned_scopes(),
    which assumes resource.owner is the scope owner — true for DID
    resources (add_rule, add_dids, ...) but not for this rule resource.
    """
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


def _kwargs_add_dids(evaluation: Evaluation) -> dict[str, Any]:
    """add_dids (authz.rego _perm_add_dids): every DID's scope owned,
    and the list non-empty — or privilege. minItems: 1 on the contract
    schema already guarantees non-empty."""
    dids = [
        {"scope": resource.attributes.get("scope"), "name": resource.id}
        for resource in evaluation.resources
    ]
    return {
        "dids": dids,
        "owned_scopes": _owned_scopes(evaluation.subject.id, evaluation.resources),
    }


def _kwargs_attach_dids_to_dids(evaluation: Evaluation) -> dict[str, Any]:
    """attach_dids_to_dids (authz.rego _perm_attach_dids_to_dids): every
    attachment's (parent) scope owned, list non-empty — or privilege.
    Only the parent's scope decides the outcome; children aren't read
    by the Rego, so they're not part of the OPA input either."""
    attachments = [
        {"scope": resource.attributes.get("scope"), "name": resource.id}
        for resource in evaluation.resources
    ]
    return {
        "attachments": attachments,
        "owned_scopes": _owned_scopes(evaluation.subject.id, evaluation.resources),
    }


def _kwargs_detach_dids(evaluation: Evaluation) -> dict[str, Any]:
    """detach_dids (authz.rego _perm_detach_dids): the parent's scope
    owned — or privilege. A single scalar scope, not a list of DID
    objects, matching input.kwargs.scope in the Rego."""
    resource = evaluation.resources[0]
    owned_scopes = _owned_scopes(evaluation.subject.id, evaluation.resources)
    return {"scope": resource.attributes.get("scope"), "owned_scopes": owned_scopes}


_KWARGS_BUILDERS: dict[str, Callable[[Evaluation], dict[str, Any]]] = {
    "del_rule": _kwargs_del_rule,
    "add_rule": _kwargs_add_rule,
    "update_rule": _kwargs_update_rule,
    "add_dids": _kwargs_add_dids,
    "attach_dids_to_dids": _kwargs_attach_dids_to_dids,
    "detach_dids": _kwargs_detach_dids,
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

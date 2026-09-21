"""Evaluation <-> OPA translation.

Evaluation -> OPA input reproduces the document phase 7's _build_input()
sent, so the unchanged vo.authz.v6 Rego keeps deciding the same way
(design-006, "The PDP port"). OPA's response -> Outcome is generic and
covers every operation.

kwargs are action-specific, so they land one operation at a time
(design-006, "Migration"). del_rule, add_rule, update_rule, add_dids,
attach_dids_to_dids, detach_dids, add_rse, update_rse, del_rse,
add_rse_attribute, del_rse_attribute, add_protocol, update_protocol
and del_protocol are registered; everything else (replicas,
privileged-operations) is still parked, and to_opa_input() raises for
any unregistered action rather than guessing a shape that could
silently flip a decision.

DID operations always dispatch to their list-capable Rego action
(add_dids, attach_dids_to_dids) regardless of how many DIDs the
request names, per design-005's "Operations sharing a Rucio action
share an endpoint" — the singular add_did/attach_dids actions are
Rucio-internal and never reached from this contract.

RSE and protocol operations are privilege-only in authz.rego — neither
table has an account column, so there's no ownership check to
translate for either. Protocols carry one extra gate on top of
privilege: _protocol_scheme_allowed, checked even for root. An absent
scheme (del_protocol, and some update_protocol calls) always passes
that check; a present scheme must be in the allowlist. Name/scheme
validity in both cases is data-driven and lives entirely in the Rego —
this module forwards the values without validating them itself.
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
    attributes["scope"]; ownership is resource.owner == subject_id.

    Not used by RSE or protocol builders — neither has an owner to
    compare against, only privilege (and, for protocols, scheme)."""
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
    rule = evaluation.resources[0]
    scope = rule.attributes.get("scope")
    scope_owner = rule.attributes.get("scope_owner")
    owned_scopes = [scope] if scope and scope_owner == evaluation.subject.id else []

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


def _kwargs_add_rse(evaluation: Evaluation) -> dict[str, Any]:
    """add_rse (authz.rego _perm_add_rse): privilege AND
    _rse_name_valid(kwargs.rse). Name validity is data-driven and
    checked entirely inside the Rego; this only forwards the name."""
    rse = evaluation.resources[0]
    return {"rse": rse.id}


def _kwargs_update_rse(evaluation: Evaluation) -> dict[str, Any]:
    """update_rse (authz.rego _perm_update_rse): privilege alone when
    not renaming (kwargs.parameters.rse absent/undefined), or privilege
    AND _rse_name_valid(kwargs.parameters.rse) when renaming. changes
    with no "name" produces parameters: {} — Rego's `not
    input.kwargs.parameters.rse` is true whether parameters itself or
    just its rse key is missing, so an empty dict is enough to signal
    "no rename" without needing to omit the key entirely."""
    rse = evaluation.resources[0]
    new_name = evaluation.context.get("new_name")
    return {"rse": rse.id, "parameters": {"rse": new_name} if new_name else {}}


def _kwargs_del_rse(evaluation: Evaluation) -> dict[str, Any]:
    """del_rse (authz.rego _perm_del_rse): privilege only. rse carried
    for audit even though the Rego doesn't read it."""
    rse = evaluation.resources[0]
    return {"rse": rse.id}


def _kwargs_add_rse_attribute(evaluation: Evaluation) -> dict[str, Any]:
    """add_rse_attribute (authz.rego _perm_add_rse_attribute): privilege
    only. key/value carried for audit even though the Rego doesn't read
    them (phase-6-era note in the contract: "value... not read by the
    phase 6 policy")."""
    rse = evaluation.resources[0]
    kwargs: dict[str, Any] = {"rse": rse.id, "key": evaluation.context.get("key")}
    value = evaluation.context.get("value")
    if value is not None:
        kwargs["value"] = value
    return kwargs


def _kwargs_del_rse_attribute(evaluation: Evaluation) -> dict[str, Any]:
    """del_rse_attribute (authz.rego _perm_del_rse_attribute): privilege
    only. key carried for audit even though the Rego doesn't read it."""
    rse = evaluation.resources[0]
    return {"rse": rse.id, "key": evaluation.context.get("key")}


def _kwargs_protocol(evaluation: Evaluation) -> dict[str, Any]:
    """Shared by add_protocol/update_protocol/del_protocol (authz.rego
    _perm_add_protocol / _perm_update_protocol / _perm_del_protocol):
    privilege AND _protocol_scheme_allowed(kwargs.scheme). Absent
    scheme (rse.attributes has no "scheme" key, or the contract's
    Protocol.scheme was itself absent from the request) always passes
    that check in the Rego — `not input.kwargs.scheme` — so kwargs.scheme
    is simply omitted rather than sent as null, matching how every
    other builder here treats "no value" for an optional field."""
    rse = evaluation.resources[0]
    kwargs: dict[str, Any] = {"rse": rse.id}
    scheme = evaluation.context.get("scheme")
    if scheme:
        kwargs["scheme"] = scheme
    return kwargs


_KWARGS_BUILDERS: dict[str, Callable[[Evaluation], dict[str, Any]]] = {
    "del_rule": _kwargs_del_rule,
    "add_rule": _kwargs_add_rule,
    "update_rule": _kwargs_update_rule,
    "add_dids": _kwargs_add_dids,
    "attach_dids_to_dids": _kwargs_attach_dids_to_dids,
    "detach_dids": _kwargs_detach_dids,
    "add_rse": _kwargs_add_rse,
    "update_rse": _kwargs_update_rse,
    "del_rse": _kwargs_del_rse,
    "add_rse_attribute": _kwargs_add_rse_attribute,
    "del_rse_attribute": _kwargs_del_rse_attribute,
    "add_protocol": _kwargs_protocol,
    "update_protocol": _kwargs_protocol,
    "del_protocol": _kwargs_protocol,
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

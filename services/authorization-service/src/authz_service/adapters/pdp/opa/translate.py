"""Evaluation <-> OPA translation.

Evaluation -> OPA input reproduces the document phase 7's _build_input()
sent, so the unchanged vo.authz.v6 Rego keeps deciding the same way
(design-006, "The PDP port"). OPA's response -> Outcome is generic and
covers every operation.

kwargs are action-specific, so they land one operation at a time
(design-006, "Migration"): only actions in _KWARGS_BUILDERS are
supported. Anything else is a deployment gap, not a PDP decision, so
to_opa_input() raises and evaluate() maps that to NOT_APPLICABLE rather
than guessing a shape that could silently flip a decision.
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


def _owned_scopes(evaluation: Evaluation) -> list[str]:
    """Scopes this request names that the subject owns.

    Phase 7 computed this with a DB lookup (_owned_scopes ->
    is_scope_owner). The contract now carries the resolved owner on the
    wire (Scope.owner), so the same comparison happens here against
    evaluation data — no DB access from the core (invariant 3).
    """
    subject_id = evaluation.subject.id
    owned: list[str] = []
    for resource in evaluation.resources:
        scope = resource.attributes.get("scope")
        owner = resource.attributes.get("scope_owner")
        if scope and owner == subject_id and scope not in owned:
            owned.append(scope)
    return owned


def _kwargs_del_rule(evaluation: Evaluation) -> dict[str, Any]:
    # Provisional: assumes the route handler builds one Resource for the
    # rule, with "scope" and "scope_owner" attributes — settle this
    # alongside api/routes/rules.py.
    rule = evaluation.resources[0]
    return {
        "rule_id": rule.id,
        "rule_owner": rule.owner,
        "rule_scope": rule.attributes.get("scope"),
        "owned_scopes": _owned_scopes(evaluation),
    }


_KWARGS_BUILDERS: dict[str, Callable[[Evaluation], dict[str, Any]]] = {
    "del_rule": _kwargs_del_rule,
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
        # OPA's convention for an undefined rule.
        return Outcome.NOT_APPLICABLE
    result = body["result"]
    if not isinstance(result, bool):
        return Outcome.INDETERMINATE
    return Outcome.PERMIT if result else Outcome.DENY

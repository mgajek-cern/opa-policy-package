"""Rules operations.

Started from the fastapi-codegen stub (api/generated/rules.py) and
moved here to be hand-maintained: `make generate-server-stubs` regenerates
that stub from the contract on every run and would overwrite any logic
added in place. Only authorize_rule_delete is real (design-006 step 2,
"rules/delete" first); create/update are parked until their turn in
the migration sequencing table.

response_model is Decision, matching the generated stub: every non-200
outcome raises ProblemError (see api/errors.py) rather than returning
a Problem, so the success path never has to satisfy response_model
with anything but a Decision. The Union[Decision, Problem] return
annotation still documents what the operation can produce per the
contract's responses={...} map, even though a Problem never actually
comes back as a return value.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from authz_service.api.errors import ProblemError
from authz_service.api.generated.models import (
    Decision,
    Problem,
    RuleCreateRequest,
    RuleDeleteRequest,
    RuleUpdateRequest,
)
from authz_service.api.generated.models import Subject as _SubjectModel
from authz_service.api.routes._responses import not_yet_implemented
from authz_service.core.model import Evaluation, Resource, Subject, grants, http_status_for
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["rules"])


def _claims(subject: _SubjectModel) -> dict[str, object]:
    token = subject.properties.token if subject.properties else None
    if token is None:
        return {}
    claims: dict[str, object] = {"iss": str(token.iss), "sub": token.sub}
    if token.jti:
        claims["jti"] = token.jti
    if token.aud:
        claims["aud"] = token.aud
    if token.entitlements:
        claims["entitlements"] = token.entitlements
    if token.acr:
        claims["acr"] = token.acr
    return claims


@router.post(
    "/v1/decisions/rules/create",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rules"],
)
async def authorize_rule_create(body: RuleCreateRequest) -> Decision | Problem:
    """May the subject create a replication rule over these DIDs?"""
    not_yet_implemented("authorizeRuleCreate")


@router.post(
    "/v1/decisions/rules/delete",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rules"],
)
async def authorize_rule_delete(body: RuleDeleteRequest, request: Request) -> Decision | Problem:
    """May the subject delete an existing rule?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="del_rule",
        subject=Subject(
            type=body.subject.type.value, id=body.subject.id, claims=_claims(body.subject)
        ),
        resources=(Resource(type="rule", id=body.rule.id, owner=body.rule.owner),),
        context={"vo": body.context.vo},
    )

    outcome = await pdp.evaluate(evaluation)
    status_code = http_status_for(outcome)
    if status_code != 200:
        raise ProblemError(status_code, "Policy decision point could not evaluate the request")
    return Decision(decision=grants(outcome))


@router.post(
    "/v1/decisions/rules/update",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rules"],
)
async def authorize_rule_update(body: RuleUpdateRequest) -> Decision | Problem:
    """May the subject change an existing rule?"""
    not_yet_implemented("authorizeRuleUpdate")

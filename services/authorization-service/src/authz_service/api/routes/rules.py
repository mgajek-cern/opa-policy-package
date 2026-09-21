"""Rules operations.

Started from the fastapi-codegen stub (api/generated/rules.py) and
moved here to be hand-maintained: `make generate-server-stubs`
regenerates that stub from the contract on every run and would
overwrite any logic added in place. All three operations are real
(design-006 step 2); rses, protocols, replicas, dids and
privileged-operations remain parked.

response_model is Decision, matching the generated stub: every non-200
outcome raises ProblemError (see api/errors.py) rather than returning
a Problem, so the success path never has to satisfy response_model
with anything but a Decision. The Decision | Problem return annotation
still documents what the operation can produce per the contract's
responses={...} map, even though a Problem never actually comes back
as a return value.
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
from authz_service.core.model import Evaluation, Resource, Subject, grants, http_status_for
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["rules"])


def _subject_from(body_subject: _SubjectModel) -> Subject:
    # TODO(authn): claims={} disables every privilege path in authz.rego
    # that reads input.token.entitlements, until api/auth.py validates
    # the caller's bearer token and extracts claims from it, per
    # design-005's Trust model / ADR-006. Only ownership paths (which
    # read body.subject.id / resource owners, not claims) and root's
    # unconditional bootstrap (input.issuer == "root") work until then.
    return Subject(type=body_subject.type.value, id=body_subject.id, claims={})


async def _decide(pdp: PolicyDecisionPoint, evaluation: Evaluation) -> Decision:
    outcome = await pdp.evaluate(evaluation)
    status_code = http_status_for(outcome)
    if status_code != 200:
        raise ProblemError(status_code, "Policy decision point could not evaluate the request")
    return Decision(decision=grants(outcome))


@router.post(
    "/v1/decisions/rules/create",
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
async def authorize_rule_create(body: RuleCreateRequest, request: Request) -> Decision | Problem:
    """May the subject create a replication rule over these DIDs?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_rule",
        subject=_subject_from(body.subject),
        resources=tuple(
            Resource(
                type="did",
                id=did.name,
                owner=did.scope.owner,
                attributes={"scope": did.scope.name},
            )
            for did in body.rule.dids
        ),
        context={
            "vo": body.context.vo,
            "account": body.rule.owner,
            "locked": body.rule.locked,
            "rse_expression": body.rule.rse_expression,
            "source_rse_expression": body.rule.source_rse_expression,
        },
    )
    return await _decide(pdp, evaluation)


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
        subject=_subject_from(body.subject),
        resources=(Resource(type="rule", id=body.rule.id, owner=body.rule.owner),),
        context={"vo": body.context.vo},
    )
    return await _decide(pdp, evaluation)


@router.post(
    "/v1/decisions/rules/update",
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
async def authorize_rule_update(body: RuleUpdateRequest, request: Request) -> Decision | Problem:
    """May the subject change an existing rule?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="update_rule",
        subject=_subject_from(body.subject),
        resources=(
            Resource(
                type="rule",
                id=body.rule.id,
                owner=body.rule.owner,
                attributes={
                    "scope": body.rule.target.scope.name,
                    "scope_owner": body.rule.target.scope.owner,
                },
            ),
        ),
        context={
            "vo": body.context.vo,
            "changes": {
                "owner": body.changes.owner,
                "lifetime": body.changes.lifetime,
                "rse_expression": body.changes.rse_expression,
            },
        },
    )
    return await _decide(pdp, evaluation)

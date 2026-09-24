"""Rules operations. Initially referring to fastapi-codegen stub routers signatures."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from authz_service.api.auth import TokenClaims, validated_claims
from authz_service.api.generated.models import (
    Decision,
    Problem,
    RuleCreateRequest,
    RuleDeleteRequest,
    RuleUpdateRequest,
)
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation, Resource
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["rules"])


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
async def authorize_rule_create(
    body: RuleCreateRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject create a replication rule over these DIDs?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_rule",
        subject=subject_from(body.subject, token),
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
    return await decide(pdp, evaluation)


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
async def authorize_rule_delete(
    body: RuleDeleteRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject delete an existing rule?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="del_rule",
        subject=subject_from(body.subject, token),
        resources=(Resource(type="rule", id=body.rule.id, owner=body.rule.owner),),
        context={"vo": body.context.vo},
    )
    return await decide(pdp, evaluation)


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
async def authorize_rule_update(
    body: RuleUpdateRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject change an existing rule?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="update_rule",
        subject=subject_from(body.subject, token),
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
    return await decide(pdp, evaluation)

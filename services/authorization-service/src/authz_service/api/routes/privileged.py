"""Privileged operations. Initially referring to fastapi-codegen stub routers signatures."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from authz_service.api.auth import TokenClaims, validated_claims
from authz_service.api.errors import ProblemError
from authz_service.api.generated.models import Decision, PrivilegedOperationRequest, Problem
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["privileged"])


@router.post(
    "/v1/decisions/privileged-operations",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["privileged"],
)
async def authorize_privileged_operation(
    body: PrivilegedOperationRequest,
    request: Request,
    token: TokenClaims = Depends(validated_claims),
) -> Decision | Problem:
    """May the subject perform an operation reserved for privileged subjects?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    # The contract reserves this endpoint for operations without their own
    # route. An operation name that collides with a typed endpoint's action
    # must be rejected here, per openapi.yaml — otherwise it silently falls
    # through to authz.rego's catch-all instead of the rule actually meant
    # to decide it.
    if body.operation in await pdp.known_actions():
        raise ProblemError(
            400,
            "operation has its own decision endpoint",
            detail=f"{body.operation!r} is not a privileged-operations action",
        )

    evaluation = Evaluation(
        operation="privileged_operation",
        subject=subject_from(body.subject, token),
        resources=(),
        context={"vo": body.context.vo, "operation": body.operation},
    )
    return await decide(pdp, evaluation)

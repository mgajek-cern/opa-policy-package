"""Protocol operations. Started from the fastapi-codegen stub."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from authz_service.api.auth import TokenClaims, validated_claims
from authz_service.api.generated.models import (
    Decision,
    Problem,
    ProtocolCreateRequest,
    ProtocolDeleteRequest,
    ProtocolUpdateRequest,
)
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation, Resource
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["protocols"])


@router.post(
    "/v1/decisions/protocols/create",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_create(
    body: ProtocolCreateRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject add a protocol to this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_protocol",
        subject=subject_from(body.subject, token),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "scheme": body.protocol.scheme},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/protocols/update",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_update(
    body: ProtocolUpdateRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject update a protocol on this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="update_protocol",
        subject=subject_from(body.subject, token),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "scheme": body.protocol.scheme},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/protocols/delete",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_delete(
    body: ProtocolDeleteRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject delete a protocol from this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="del_protocol",
        subject=subject_from(body.subject, token),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "scheme": body.protocol.scheme},
    )
    return await decide(pdp, evaluation)

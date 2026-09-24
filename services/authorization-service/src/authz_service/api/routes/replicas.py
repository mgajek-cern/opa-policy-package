"""Replica operations. Started from the fastapi-codegen stub."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from authz_service.api.auth import TokenClaims, validated_claims
from authz_service.api.generated.models import (
    Decision,
    Problem,
    ReplicaDeleteRequest,
    ReplicaRegisterRequest,
)
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation, Resource
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["replicas"])


@router.post(
    "/v1/decisions/replicas/register",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["replicas"],
)
async def authorize_replica_register(
    body: ReplicaRegisterRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject register replicas of these files on this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_replicas",
        subject=subject_from(body.subject, token),
        resources=tuple(
            Resource(
                type="did",
                id=file.name,
                owner=file.scope.owner,
                attributes={"scope": file.scope.name},
            )
            for file in body.files
        ),
        context={"vo": body.context.vo, "rse": body.rse.name},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/replicas/delete",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["replicas"],
)
async def authorize_replica_delete(
    body: ReplicaDeleteRequest, request: Request, token: TokenClaims = Depends(validated_claims)
) -> Decision | Problem:
    """May the subject delete replicas of these files on this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="delete_replicas",
        subject=subject_from(body.subject, token),
        resources=tuple(
            Resource(
                type="did",
                id=file.name,
                owner=file.scope.owner,
                attributes={"scope": file.scope.name},
            )
            for file in body.files
        ),
        context={"vo": body.context.vo, "rse": body.rse.name},
    )
    return await decide(pdp, evaluation)

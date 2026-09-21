"""Replica operations"""

from __future__ import annotations

from fastapi import APIRouter

from authz_service.api.generated.models import (
    Decision,
    Problem,
    ReplicaDeleteRequest,
    ReplicaRegisterRequest,
)
from authz_service.api.routes._responses import not_yet_implemented

router = APIRouter(tags=["replicas"])


@router.post(
    "/v1/decisions/replicas/delete",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["replicas"],
)
async def authorize_replica_delete(body: ReplicaDeleteRequest) -> Decision | Problem:
    """May the subject delete replicas of these files on this RSE?"""
    not_yet_implemented("authorizeReplicaDelete")


@router.post(
    "/v1/decisions/replicas/register",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["replicas"],
)
async def authorize_replica_register(body: ReplicaRegisterRequest) -> Decision | Problem:
    """May the subject register replicas of these files on this RSE?"""
    not_yet_implemented("authorizeReplicaRegister")

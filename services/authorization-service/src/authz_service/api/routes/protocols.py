"""Protocol operations"""

from __future__ import annotations

from fastapi import APIRouter

from authz_service.api.generated.models import (
    Decision,
    Problem,
    ProtocolCreateRequest,
    ProtocolDeleteRequest,
    ProtocolUpdateRequest,
)
from authz_service.api.routes._responses import not_yet_implemented

router = APIRouter(tags=["protocols"])


@router.post(
    "/v1/decisions/protocols/create",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_create(body: ProtocolCreateRequest) -> Decision | Problem:
    """May the subject add a protocol to this RSE?"""
    not_yet_implemented("authorizeProtocolCreate")


@router.post(
    "/v1/decisions/protocols/delete",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_delete(body: ProtocolDeleteRequest) -> Decision | Problem:
    """May the subject delete a protocol from this RSE?"""
    not_yet_implemented("authorizeProtocolDelete")


@router.post(
    "/v1/decisions/protocols/update",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_update(body: ProtocolUpdateRequest) -> Decision | Problem:
    """May the subject update a protocol on this RSE?"""
    not_yet_implemented("authorizeProtocolUpdate")

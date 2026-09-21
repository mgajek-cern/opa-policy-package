"""RSE operations"""

from __future__ import annotations

from fastapi import APIRouter

from authz_service.api.generated.models import (
    Decision,
    Problem,
    RseAttributeDeleteRequest,
    RseAttributeSetRequest,
    RseCreateRequest,
    RseDeleteRequest,
    RseUpdateRequest,
)
from authz_service.api.routes._responses import not_yet_implemented

router = APIRouter(tags=["rses"])


@router.post(
    "/v1/decisions/rses/attributes/delete",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_attribute_delete(body: RseAttributeDeleteRequest) -> Decision | Problem:
    """May the subject delete an attribute from this RSE?"""
    not_yet_implemented("authorizeRseAttributeDelete")


@router.post(
    "/v1/decisions/rses/attributes/set",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_attribute_set(body: RseAttributeSetRequest) -> Decision | Problem:
    """May the subject set an attribute on this RSE?"""
    not_yet_implemented("authorizeRseAttributeSet")


@router.post(
    "/v1/decisions/rses/create",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_create(body: RseCreateRequest) -> Decision | Problem:
    """May the subject create an RSE with this name?"""
    not_yet_implemented("authorizeRseCreate")


@router.post(
    "/v1/decisions/rses/delete",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_delete(body: RseDeleteRequest) -> Decision | Problem:
    """May the subject delete this RSE?"""
    not_yet_implemented("authorizeRseDelete")


@router.post(
    "/v1/decisions/rses/update",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_update(body: RseUpdateRequest) -> Decision | Problem:
    """May the subject update this RSE, including a rename?"""
    not_yet_implemented("authorizeRseUpdate")

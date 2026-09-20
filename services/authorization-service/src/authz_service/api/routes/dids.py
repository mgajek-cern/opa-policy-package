"""DID operations, parked until their turn in the migration sequencing
table (design-006). Started from the fastapi-codegen stub
(api/generated/dids.py), moved here per rules.py.
"""

from __future__ import annotations

from fastapi import APIRouter

from authz_service.api.generated.models import (
    Decision,
    DidAttachRequest,
    DidCreateRequest,
    DidDetachRequest,
    Problem,
)
from authz_service.api.routes._responses import not_yet_implemented

router = APIRouter(tags=["dids"])


@router.post(
    "/v1/decisions/dids/create",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["dids"],
)
async def authorize_did_create(body: DidCreateRequest) -> Decision | Problem:
    """May the subject create these DIDs?"""
    not_yet_implemented("authorizeDidCreate")


@router.post(
    "/v1/decisions/dids/attach",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["dids"],
)
async def authorize_did_attach(body: DidAttachRequest) -> Decision | Problem:
    """May the subject attach children to these parent DIDs?"""
    not_yet_implemented("authorizeDidAttach")


@router.post(
    "/v1/decisions/dids/detach",
    response_model=Decision,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["dids"],
)
async def authorize_did_detach(body: DidDetachRequest) -> Decision | Problem:
    """May the subject detach children from a parent DID?"""
    not_yet_implemented("authorizeDidDetach")

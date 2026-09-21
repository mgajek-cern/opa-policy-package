"""Privileged operations"""

from __future__ import annotations

from fastapi import APIRouter

from authz_service.api.generated.models import Decision, PrivilegedOperationRequest, Problem
from authz_service.api.routes._responses import not_yet_implemented

router = APIRouter(tags=["privileged"])


@router.post(
    "/v1/decisions/privileged-operations",
    response_model=Decision,
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
) -> Decision | Problem:
    """May the subject perform an operation reserved for privileged subjects?"""
    not_yet_implemented("authorizePrivilegedOperation")

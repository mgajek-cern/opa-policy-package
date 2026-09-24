"""Operations. Initially referring to fastapi-codegen stub routers signatures."""

from __future__ import annotations

from fastapi import APIRouter, Request

from authz_service.api.errors import ProblemError
from authz_service.api.generated.models import HealthStatus, Problem
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["operations"])


@router.get(
    "/healthz",
    response_model=HealthStatus,
    responses={
        "503": {"model": Problem},
    },
    tags=["operations"],
)
async def get_health(request: Request) -> HealthStatus | Problem:
    """Liveness and PDP reachability"""
    pdp: PolicyDecisionPoint = request.app.state.pdp
    if not await pdp.is_available():
        raise ProblemError(503, "Policy decision point unavailable")
    return HealthStatus(status="ok")

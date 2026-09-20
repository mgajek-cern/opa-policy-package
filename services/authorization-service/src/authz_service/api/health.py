"""Liveness and PDP reachability."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from authz_service.api.errors import problem
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter()


@router.get("/healthz", include_in_schema=True)
async def healthz(request: Request) -> JSONResponse:
    pdp: PolicyDecisionPoint = request.app.state.pdp
    if not await pdp.is_available():
        return problem(503, "Policy decision point unavailable")
    return JSONResponse({"status": "ok"})

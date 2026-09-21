"""Started from the fastapi-codegen stub."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["operations"])


@router.get("/healthz", response_model=None, tags=["operations"])
async def get_health() -> None:
    """
    Liveness and PDP reachability
    """
    pass

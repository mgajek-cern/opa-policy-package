"""Shared helper for parked operations"""

from __future__ import annotations

from typing import NoReturn

from authz_service.api.errors import ProblemError


def not_yet_implemented(operation_id: str) -> NoReturn:
    """Parked operations answer honestly (501) instead of 404ing, and
    stay served by the phase 6 direct-OPA path."""
    raise ProblemError(
        501,
        "Operation not yet migrated to the authorization service",
        detail=f"{operation_id} is still served by the phase 6 direct-OPA path.",
    )

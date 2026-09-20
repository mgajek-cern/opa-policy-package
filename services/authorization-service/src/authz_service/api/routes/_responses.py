"""Shared helper for parked operations (design-006 'Migration').

Raises rather than returns, so a route's success path stays a plain
Decision and response_model=Decision stays accurate — see
api/errors.ProblemError.
"""

from __future__ import annotations

from typing import NoReturn

from authz_service.api.errors import ProblemError


def not_yet_implemented(operation_id: str) -> NoReturn:
    """Parked operations answer honestly (501) instead of 404ing, and
    stay served by the phase 7 direct-OPA path."""
    raise ProblemError(
        501,
        "Operation not yet migrated to the authorization service",
        detail=f"{operation_id} is still served by the phase 7 direct-OPA path.",
    )

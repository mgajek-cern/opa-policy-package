"""Ports the core defines and adapters implement."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from authz_service.core.model import Evaluation, Outcome


@runtime_checkable
class PolicyDecisionPoint(Protocol):
    """The one outbound boundary of the service (ADR-004)."""

    async def evaluate(self, evaluation: Evaluation) -> Outcome:
        """Decide one evaluation. Never raises: failures map to an Outcome."""
        ...

    async def is_available(self) -> bool:
        """Whether the PDP is reachable. Used by the health endpoint."""
        ...

    async def policy_revision(self) -> str | None:
        """The deployed policy revision, for audit records."""
        ...

    async def known_actions(self) -> frozenset[str]:
        """The actions the deployed policy knows, for the alignment check."""
        ...

"""The decision model.

PDP-neutral by design: nothing here knows about OPA, HTTP or pydantic
(ADR-004, invariant 3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Outcome(StrEnum):
    """What the PDP concluded, in XACML's categories.

    Every PDP adapter maps its own answers onto these, so the core never
    sees PDP-specific results (design-006, "The PDP port").
    """

    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class Subject:
    """The principal a decision is about."""

    type: str
    id: str
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    """One resource a request names, with the owner the PEP resolved."""

    type: str
    id: str
    owner: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evaluation:
    """One decision request: who, what, on which resources."""

    operation: str
    subject: Subject
    resources: tuple[Resource, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """The answer returned to the PEP."""

    allowed: bool
    outcome: Outcome
    decision_id: str
    reason_admin: str = ""
    policy_id: str | None = None
    policy_revision: str | None = None


# Invariant 1: only PERMIT grants. Everything else is a deny or an error,
# and the PEP treats every error as a deny.
_STATUS_BY_OUTCOME: dict[Outcome, int] = {
    Outcome.PERMIT: 200,
    Outcome.DENY: 200,
    # No applicable policy is a deployment fault, not a decision.
    Outcome.NOT_APPLICABLE: 500,
    Outcome.INDETERMINATE: 503,
}


def http_status_for(outcome: Outcome) -> int:
    """The HTTP status an outcome produces."""
    return _STATUS_BY_OUTCOME[outcome]


def grants(outcome: Outcome) -> bool:
    """Whether an outcome grants access. Only PERMIT does."""
    return outcome is Outcome.PERMIT

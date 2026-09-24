"""Shared helpers for routes that call the PDP: building a core Subject
from the generated request model, and turning a PDP outcome into a
Decision or a raised ProblemError. Used by every router with a real
(non-parked) operation, so this logic lives in one place rather than
once per router file.
"""

from __future__ import annotations

from authz_service.api.auth import TokenClaims
from authz_service.api.errors import ProblemError
from authz_service.api.generated.models import Decision
from authz_service.api.generated.models import Subject as _SubjectModel
from authz_service.core.model import Evaluation, Subject, grants, http_status_for
from authz_service.core.ports import PolicyDecisionPoint


def subject_from(body_subject: _SubjectModel, token: TokenClaims) -> Subject:
    return Subject(
        type=body_subject.type.value,
        id=body_subject.id,
        claims={
            "entitlements": token.entitlements,
            "acr": token.acr,
            **({"act": token.actor_sub} if token.actor_sub else {}),
        },
    )


async def decide(pdp: PolicyDecisionPoint, evaluation: Evaluation) -> Decision:
    outcome = await pdp.evaluate(evaluation)
    status_code = http_status_for(outcome)
    if status_code != 200:
        raise ProblemError(status_code, "Policy decision point could not evaluate the request")
    return Decision(decision=grants(outcome))

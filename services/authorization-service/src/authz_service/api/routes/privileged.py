"""Privileged operations.

Started from the fastapi-codegen stub (api/generated/privileged.py),
moved here per rules.py. The catch-all for every consumer action
without its own typed endpoint (design-005) — the last route in the
contract; every other operation is now real.

Evaluation.operation is the fixed internal marker
"privileged_operation" (matching translate.py's _KWARGS_BUILDERS key),
not body.operation — the consumer-chosen string (e.g. "add_account")
travels in evaluation.context["operation"] instead, and translate.py
substitutes it into the actual OPA input's "action" field. See
translate.py's to_opa_input for why.

Not yet implemented: the contract's stated "a request naming an
operation that has its own endpoint is rejected with 400" behavior.
authz.rego's catch-all denies such a request (its dispatch never
matches, so default allow := false applies) rather than erroring, and
this route doesn't intercept that case to produce a 400 instead — it
would need this service's own copy of _all_known_actions, or a call
to PolicyDecisionPoint.known_actions() before evaluating, either of
which is more than this pass builds. Flagged, not silently assumed
covered.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from authz_service.api.generated.models import Decision, PrivilegedOperationRequest, Problem
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["privileged"])


@router.post(
    "/v1/decisions/privileged-operations",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["privileged"],
)
async def authorize_privileged_operation(
    body: PrivilegedOperationRequest, request: Request
) -> Decision | Problem:
    """May the subject perform an operation reserved for privileged subjects?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="privileged_operation",
        subject=subject_from(body.subject),
        resources=(),
        context={"vo": body.context.vo, "operation": body.operation},
    )
    return await decide(pdp, evaluation)

"""Protocol operations.

Started from the fastapi-codegen stub (api/generated/protocols.py),
moved here per rules.py. All three operations are real (design-006
step 2); replicas and privileged-operations remain parked.

Protocols are privilege-only in authz.rego, like RSEs — protocols
belong to RSEs, which have no account column. On top of privilege,
every protocol action also requires _protocol_scheme_allowed: an
absent scheme always passes, a present one must be in the allowlist
(default or bundle-provided). This second gate applies even to root.
Every route still inherits the claims={} gap from _pdp.subject_from:
until api/auth.py lands, only root's unconditional bootstrap
(input.issuer == "root") can pass the privilege half of that check.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from authz_service.api.generated.models import (
    Decision,
    Problem,
    ProtocolCreateRequest,
    ProtocolDeleteRequest,
    ProtocolUpdateRequest,
)
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation, Resource
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["protocols"])


@router.post(
    "/v1/decisions/protocols/create",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_create(
    body: ProtocolCreateRequest, request: Request
) -> Decision | Problem:
    """May the subject add a protocol to this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_protocol",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "scheme": body.protocol.scheme},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/protocols/update",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_update(
    body: ProtocolUpdateRequest, request: Request
) -> Decision | Problem:
    """May the subject update a protocol on this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="update_protocol",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "scheme": body.protocol.scheme},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/protocols/delete",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["protocols"],
)
async def authorize_protocol_delete(
    body: ProtocolDeleteRequest, request: Request
) -> Decision | Problem:
    """May the subject delete a protocol from this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="del_protocol",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "scheme": body.protocol.scheme},
    )
    return await decide(pdp, evaluation)

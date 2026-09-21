"""DID operations."""

from __future__ import annotations

from fastapi import APIRouter, Request

from authz_service.api.generated.models import (
    Decision,
    DidAttachRequest,
    DidCreateRequest,
    DidDetachRequest,
    Problem,
)
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation, Resource
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["dids"])


@router.post(
    "/v1/decisions/dids/create",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["dids"],
)
async def authorize_did_create(body: DidCreateRequest, request: Request) -> Decision | Problem:
    """May the subject create these DIDs?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_dids",
        subject=subject_from(body.subject),
        resources=tuple(
            Resource(
                type="did",
                id=did.name,
                owner=did.scope.owner,
                attributes={"scope": did.scope.name},
            )
            for did in body.dids
        ),
        context={"vo": body.context.vo},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/dids/attach",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["dids"],
)
async def authorize_did_attach(body: DidAttachRequest, request: Request) -> Decision | Problem:
    """May the subject attach children to these parent DIDs?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="attach_dids_to_dids",
        subject=subject_from(body.subject),
        resources=tuple(
            Resource(
                type="did",
                id=attachment.parent.name,
                owner=attachment.parent.scope.owner,
                attributes={"scope": attachment.parent.scope.name},
            )
            for attachment in body.attachments
        ),
        context={"vo": body.context.vo},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/dids/detach",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["dids"],
)
async def authorize_did_detach(body: DidDetachRequest, request: Request) -> Decision | Problem:
    """May the subject detach children from a parent DID?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="detach_dids",
        subject=subject_from(body.subject),
        resources=(
            Resource(
                type="did",
                id=body.parent.name,
                owner=body.parent.scope.owner,
                attributes={"scope": body.parent.scope.name},
            ),
        ),
        context={"vo": body.context.vo},
    )
    return await decide(pdp, evaluation)

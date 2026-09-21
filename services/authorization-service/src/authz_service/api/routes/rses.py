"""RSE operations. Started from the fastapi-codegen stub (api/generated/rses.py)."""

from __future__ import annotations

from fastapi import APIRouter, Request

from authz_service.api.generated.models import (
    Decision,
    Problem,
    RseAttributeDeleteRequest,
    RseAttributeSetRequest,
    RseCreateRequest,
    RseDeleteRequest,
    RseUpdateRequest,
)
from authz_service.api.routes._pdp import decide, subject_from
from authz_service.core.model import Evaluation, Resource
from authz_service.core.ports import PolicyDecisionPoint

router = APIRouter(tags=["rses"])


@router.post(
    "/v1/decisions/rses/create",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_create(body: RseCreateRequest, request: Request) -> Decision | Problem:
    """May the subject create an RSE with this name?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_rse",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/rses/update",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_update(body: RseUpdateRequest, request: Request) -> Decision | Problem:
    """May the subject update this RSE, including a rename?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="update_rse",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "new_name": body.changes.name},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/rses/delete",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_delete(body: RseDeleteRequest, request: Request) -> Decision | Problem:
    """May the subject delete this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="del_rse",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo},
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/rses/attributes/set",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_attribute_set(
    body: RseAttributeSetRequest, request: Request
) -> Decision | Problem:
    """May the subject set an attribute on this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="add_rse_attribute",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={
            "vo": body.context.vo,
            "key": body.attribute.key,
            "value": body.attribute.value,
        },
    )
    return await decide(pdp, evaluation)


@router.post(
    "/v1/decisions/rses/attributes/delete",
    response_model=Decision,
    response_model_exclude_none=True,
    responses={
        "400": {"model": Problem},
        "401": {"model": Problem},
        "403": {"model": Problem},
        "500": {"model": Problem},
    },
    tags=["rses"],
)
async def authorize_rse_attribute_delete(
    body: RseAttributeDeleteRequest, request: Request
) -> Decision | Problem:
    """May the subject delete an attribute from this RSE?"""
    pdp: PolicyDecisionPoint = request.app.state.pdp

    evaluation = Evaluation(
        operation="del_rse_attribute",
        subject=subject_from(body.subject),
        resources=(Resource(type="rse", id=body.rse.name, owner=None),),
        context={"vo": body.context.vo, "key": body.attribute.key},
    )
    return await decide(pdp, evaluation)

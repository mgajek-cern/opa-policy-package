"""RFC 9457 problem responses."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)

PROBLEM_MEDIA_TYPE = "application/problem+json"


def problem(status: int, title: str, detail: str | None = None) -> JSONResponse:
    body: dict[str, object] = {"type": "about:blank", "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type=PROBLEM_MEDIA_TYPE)


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # A fault, never a decision: the PEP treats any error as a deny.
        log.exception("unhandled error on %s", request.url.path)
        return problem(500, "Internal error")

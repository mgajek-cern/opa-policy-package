"""Composition root: the only module that knows every piece."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from authz_service.adapters.pdp.opa import OpaPolicyDecisionPoint
from authz_service.api import health
from authz_service.api.errors import install_handlers
from authz_service.api.routes import dids, privileged, protocols, replicas, rses, rules
from authz_service.core.ports import PolicyDecisionPoint
from authz_service.settings import OpaSettings, Settings
from authz_service.telemetry import setup as telemetry


def build_pdp(settings: Settings) -> PolicyDecisionPoint:
    """The one place a PDP adapter is chosen."""
    if settings.pdp == "opa":
        opa = OpaSettings()  # type: ignore[call-arg]  # values come from the environment
        return OpaPolicyDecisionPoint(
            url=opa.url,
            policy_path=opa.policy_path,
            timeout_seconds=settings.pdp_timeout_seconds,
        )
    raise ValueError(f"unknown PDP adapter: {settings.pdp!r}")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    telemetry.configure(settings.service_name)
    pdp = build_pdp(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        app.state.pdp = pdp
        yield
        aclose = getattr(pdp, "aclose", None)
        if aclose is not None:
            await aclose()

    app = FastAPI(
        title="DEP Authorization Service",
        version="0.1.0",
        lifespan=lifespan,
        # The hand-written contract is the source of truth; this app's
        # generated schema is only a convenience.
        docs_url="/docs",
    )
    install_handlers(app)
    app.include_router(health.router)
    app.include_router(dids.router)
    app.include_router(privileged.router)
    app.include_router(protocols.router)
    app.include_router(replicas.router)
    app.include_router(rses.router)
    app.include_router(rules.router)
    telemetry.instrument(app)
    return app

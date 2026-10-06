"""Control plane: identity provider, device registry, policy store and PDP."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from zta.common.config import settings
from zta.common.database import SessionLocal, init_db
from zta.common.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from zta.control_plane.bootstrap import bootstrap
from zta.control_plane.routers import auth, decisions, devices, insights, policies

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

DESCRIPTION = """
Control plane for a zero-trust access gateway.

It issues identities (JWT + optional TOTP), registers devices and their posture,
stores versioned access policies, and acts as the **policy decision point**: the
gateway asks `POST /internal/authorize` about every request and forwards only
what comes back ALLOW.

Nothing is trusted because of where it came from. Each request is scored from
identity, device posture, MFA and source network, and matched against policies
that default to deny.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as db:
        bootstrap(db)
    logger.info("control plane ready (environment=%s)", settings.environment)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=f"{settings.app_name} — control plane",
        description=DESCRIPTION,
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Device-Id"],
    )

    for module in (auth, devices, policies, decisions, insights):
        app.include_router(module.router)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Validation failed",
                "errors": [
                    {"field": ".".join(str(p) for p in err["loc"][1:]), "message": err["msg"]}
                    for err in exc.errors()
                ],
            },
        )

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok", "component": "control-plane", "environment": settings.environment}

    return app


app = create_app()

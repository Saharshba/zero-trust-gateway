"""The policy enforcement point.

Every request arrives here. The gateway itself decides nothing: it collects the
request's identity material, asks the control plane, and forwards only what
comes back ALLOW. Internal services are not reachable any other way - they sit
on a Docker network with no published ports and additionally verify the
gateway's HMAC.

    client ──► gateway ──► PDP (control plane)
                  │            │
                  │◄───────────┘  ALLOW + upstream
                  ▼
            internal service
"""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from zta.common.config import settings
from zta.common.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from zta.common.security import sign_request
from zta.gateway.pdp_client import PdpClient

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("gateway")

# Hop-by-hop headers must not be forwarded (RFC 7230 §6.1), and the client's
# own Host header would confuse the upstream.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pdp = PdpClient()
    app.state.upstream = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)
    logger.info("gateway ready; PDP at %s", settings.control_plane_url)
    try:
        yield
    finally:
        await app.state.pdp.aclose()
        await app.state.upstream.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title=f"{settings.app_name} — gateway",
        description="Policy enforcement point. Every request is authorised before it is forwarded.",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,          # the gateway is a proxy, not an API surface
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Device-Id", "X-Request-ID"],
    )

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "component": "gateway"}

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def proxy(full_path: str, request: Request) -> Response:
        started = time.perf_counter()
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        path = "/" + full_path.lstrip("/")
        body = await request.body()

        payload = {
            "request_id": request_id,
            "method": request.method,
            "path": path,
            "source_ip": client_ip(request),
            "access_token": bearer_token(request),
            "device_id": request.headers.get("x-device-id"),
            "user_agent": request.headers.get("user-agent", "")[:255],
        }

        try:
            decision = await request.app.state.pdp.authorize(payload)
        except httpx.HTTPError as exc:
            # Fail closed. A gateway that allows traffic when it cannot reach
            # the PDP is not a zero-trust gateway.
            logger.error("PDP unreachable (%s); denying %s %s", exc, request.method, path)
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Authorisation service unavailable; request denied",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )

        headers = {
            "X-Request-ID": request_id,
            "X-ZTA-Decision": decision["decision"],
            "X-ZTA-Trust-Score": str(decision.get("trust_score", 0)),
        }
        if decision.get("matched_policy"):
            headers["X-ZTA-Policy"] = decision["matched_policy"]

        if decision["decision"] != "ALLOW":
            status_code = 401 if decision.get("username", "anonymous") == "anonymous" else 403
            return JSONResponse(
                status_code=status_code,
                content={
                    "detail": "Access denied by policy",
                    "reason": decision["reason"],
                    "resource": decision.get("resource"),
                    "trust_score": decision.get("trust_score", 0),
                    "request_id": request_id,
                },
                headers=headers,
            )

        upstream_url = decision["upstream_url"].rstrip("/") + decision["upstream_path"]
        signature, timestamp = sign_request(request.method, decision["upstream_path"])
        forward_headers = {
            key: value for key, value in request.headers.items() if key.lower() not in HOP_BY_HOP
        }
        forward_headers.update(
            {
                # The upstream never sees the user's token; it sees only what
                # the gateway asserts about the caller.
                "X-Gateway-Signature": signature,
                "X-Gateway-Timestamp": timestamp,
                "X-ZTA-User": decision.get("username", ""),
                "X-ZTA-Role": decision.get("role", ""),
                "X-ZTA-Trust-Score": str(decision.get("trust_score", 0)),
                "X-Request-ID": request_id,
            }
        )
        forward_headers.pop("authorization", None)

        try:
            upstream_response = await request.app.state.upstream.request(
                request.method,
                upstream_url,
                content=body or None,
                headers=forward_headers,
                params=dict(request.query_params),
            )
        except httpx.HTTPError as exc:
            logger.error("upstream %s failed: %s", upstream_url, exc)
            return JSONResponse(
                status_code=502,
                content={"detail": "Upstream service unavailable", "request_id": request_id},
                headers=headers,
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        headers["X-Response-Time-ms"] = f"{elapsed_ms:.1f}"
        response_headers = {
            key: value
            for key, value in upstream_response.headers.items()
            if key.lower() not in HOP_BY_HOP
        }
        response_headers.update(headers)
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

    return app


app = create_app()

"""A stand-in internal service, run three times behind the gateway.

Two properties matter for the demonstration:

1. It has **no authentication of its own** — like most internal services that
   were built when the network perimeter was the security boundary.
2. It still refuses anything that did not come through the gateway, by checking
   the HMAC signature. That is defence in depth: even an attacker who lands on
   the internal Docker network cannot call it directly.

    SERVICE_NAME=reports SERVICE_PORT=9002 python -m zta.services.internal_service
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request, status

from zta.common.security import verify_signature

SERVICE_NAME = os.getenv("SERVICE_NAME", "internal")
SERVICE_TITLE = os.getenv("SERVICE_TITLE", f"{SERVICE_NAME.title()} service")

# Canned content so each service is visibly distinct in the demo.
PAYLOADS = {
    "public": {
        "service": "public",
        "classification": "PUBLIC",
        "message": "Status page. Any authenticated identity may read this.",
        "items": [
            {"component": "gateway", "status": "operational"},
            {"component": "reports", "status": "operational"},
        ],
    },
    "reports": {
        "service": "reports",
        "classification": "INTERNAL",
        "message": "Internal reporting service.",
        "items": [
            {"id": "Q1-revenue", "owner": "finance", "rows": 1284},
            {"id": "headcount", "owner": "people-ops", "rows": 97},
        ],
    },
    "admin": {
        "service": "admin",
        "classification": "RESTRICTED",
        "message": "Administrative console.",
        "items": [
            {"action": "rotate-keys", "last_run": "2026-02-11"},
            {"action": "review-access", "last_run": "2026-03-01"},
        ],
    },
}


def create_app(service_name: str = SERVICE_NAME) -> FastAPI:
    app = FastAPI(title=SERVICE_TITLE, version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "component": service_name}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def handle(
        path: str,
        request: Request,
        x_gateway_signature: str = Header(default=""),
        x_gateway_timestamp: str = Header(default=""),
        x_zta_user: str = Header(default=""),
        x_zta_role: str = Header(default=""),
        x_zta_trust_score: str = Header(default="0"),
    ) -> dict:
        request_path = "/" + path.lstrip("/")
        if not verify_signature(request.method, request_path, x_gateway_signature, x_gateway_timestamp):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This service only accepts requests forwarded by the access gateway",
            )
        return {
            **PAYLOADS.get(service_name, {"service": service_name}),
            "path": request_path,
            "method": request.method,
            "served_at": datetime.now(timezone.utc).isoformat(),
            "caller": {"user": x_zta_user, "role": x_zta_role, "trust_score": x_zta_trust_score},
        }

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", "9000")))

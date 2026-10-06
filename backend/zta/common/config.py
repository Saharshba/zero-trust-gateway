"""Settings shared by the control plane, the gateway and the demo services."""
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Zero-Trust Network Access Gateway"
    environment: str = "development"
    debug: bool = False

    database_url: str = "postgresql+psycopg://zta:zta_password@localhost:5432/zta"
    db_echo: bool = False

    redis_url: str = "redis://localhost:6379/0"
    redis_enabled: bool = True

    # --- tokens ---------------------------------------------------------
    secret_key: str = "change-me-in-production-please-32-chars"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "zta-control-plane"
    jwt_audience: str = "zta-gateway"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    bcrypt_rounds: int = 12

    # --- gateway --------------------------------------------------------
    # The gateway (policy enforcement point) asks the control plane (policy
    # decision point) about every request it has not cached.
    control_plane_url: str = "http://control-plane:8000"
    pdp_timeout_seconds: float = 3.0
    decision_cache_seconds: int = 5
    # HMAC shared with the internal services so they can reject any request
    # that did not come through the gateway.
    gateway_signing_key: str = "change-me-gateway-signing-key"
    gateway_signature_ttl_seconds: int = 30
    upstream_timeout_seconds: float = 10.0

    # --- hardening ------------------------------------------------------
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    rate_limit_requests: int = 240
    rate_limit_window_seconds: int = 60
    login_rate_limit_requests: int = 8
    login_rate_limit_window_seconds: int = 300
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # --- bootstrap ------------------------------------------------------
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "ChangeMe!123"
    bootstrap_admin_email: str = "admin@example.com"
    seed_demo_data: bool = True

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split(cls, value):
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

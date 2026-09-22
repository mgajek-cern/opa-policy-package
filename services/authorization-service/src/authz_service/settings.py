"""Environment-driven configuration, validated at startup."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class OpaSettings(BaseSettings):
    """Settings of the OPA adapter. Namespaced per adapter."""

    model_config = SettingsConfigDict(env_prefix="AUTHZ_OPA_", extra="ignore")

    url: str
    policy_path: str = "vo/authz/v6/allow"


class Settings(BaseSettings):
    """Service settings. Adapter settings are read by the adapter itself."""

    model_config = SettingsConfigDict(env_prefix="AUTHZ_", extra="ignore")

    pdp: str = "opa"
    pdp_timeout_seconds: float = 1.0

    # Required from the step where PEP authentication lands; until then the
    # service exposes only the health endpoint, which is unauthenticated.
    oidc_issuer: str
    oidc_audience: str
    required_scopes: list[str] = [
        "entitlements",
        "storage.read:/data",
        "storage.read",
        "storage.modify:/",
        "wlcg",
        "storage.modify:/data",
        "fts",
        "storage.modify",
        "storage.read:/",
    ]

    service_name: str = "authz-service"


@lru_cache
def get_settings() -> Settings:
    return Settings()

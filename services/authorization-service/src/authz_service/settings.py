"""Environment-driven configuration, validated at startup."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class OpaSettings(BaseSettings):
    """Settings of the OPA adapter. Namespaced per adapter."""

    model_config = SettingsConfigDict(env_prefix="AUTHZ_OPA_", extra="ignore")

    url: str
    policy_path: str = "vo/authz/v5/allow"


class Settings(BaseSettings):
    """Service settings. Adapter settings are read by the adapter itself."""

    model_config = SettingsConfigDict(env_prefix="AUTHZ_", extra="ignore")

    pdp: str = "opa"
    pdp_timeout_seconds: float = 1.0

    # Required from the step where PEP authentication lands; until then the
    # service exposes only the health endpoint, which is unauthenticated.
    oidc_issuer: str
    oidc_audience: str
    # Only pep:rucio identifies a PEP calling this service (design-005,
    # openapi.yaml's security scheme). The other scopes on a Rucio-minted
    # token (entitlements, storage.*, wlcg, fts) are unrelated to whether
    # the caller is authorized to reach authz-service at all.
    required_scopes: list[str] = ["pep:rucio"]

    service_name: str = "authz-service"


@lru_cache
def get_settings() -> Settings:
    return Settings()

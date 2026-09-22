# api/auth.py
"""Offline bearer-token validation, per design-005's Trust model /
ADR-006. Verifies signature against the issuer's JWKS, audience and
scope, then extracts exactly the claims authz.rego reads
(entitlements, acr) plus an actor identifier for the relaying party.

RFC 8693's `act.sub` is the spec-correct home for this, but Keycloak's
legacy (V1) token exchange — which is what this realm runs — doesn't
implement delegation and never sets `act` (see the standard-vs-legacy
comparison in Keycloak's token exchange docs). `azp` is used as a
fallback: it names the client that presented the token, which for an
exchanged token is the client that submitted the exchange request.

Caveat: `azp` is present on every token, not only exchanged ones, so
`actor_sub` being non-None does NOT by itself mean the token went
through delegated exchange — for a token issued directly to `rucio`
via password grant, `azp` is also `"rucio"`. It only diverges from the
original issuing client when a *different* client (e.g. `fts`) is the
one that requested the exchange. Callers should not treat
`actor_sub is not None` as a delegation signal on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import jwt
from fastapi import Depends, Request
from jwt import PyJWKClient

from authz_service.api.errors import ProblemError
from authz_service.settings import Settings, get_settings


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    entitlements: list[str] = field(default_factory=list)
    acr: str | None = None
    actor_sub: str | None = None  # act.sub, falling back to azp — None only if neither is present


_jwk_client: PyJWKClient | None = None


def _jwks(settings: Settings) -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(f"{settings.oidc_issuer}/protocol/openid-connect/certs")
    return _jwk_client


async def validated_claims(
    request: Request,
    settings: Settings = Depends(get_settings),  # noqa: B008 — FastAPI DI idiom
) -> TokenClaims:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise ProblemError(401, "Missing bearer token")
    token = header.removeprefix("Bearer ").removeprefix("bearer ")

    try:
        key = _jwks(settings).get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise ProblemError(401, f"Invalid token: {exc}") from exc

    if settings.required_scope not in payload.get("scope", "").split():
        raise ProblemError(403, "Token lacks required scope")

    act = payload.get("act")
    actor_sub = act.get("sub") if isinstance(act, dict) else None
    if actor_sub is None:
        actor_sub = payload.get("azp")

    return TokenClaims(
        sub=payload["sub"],
        entitlements=payload.get("entitlements", []),
        acr=payload.get("acr"),
        actor_sub=actor_sub,
    )

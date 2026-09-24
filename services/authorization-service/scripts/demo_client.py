#!/usr/bin/env python
"""Manual smoke test against a running authz-service, using the generated
client (clients/python) — the same way tests/integration/test_client_e2e.py
does, but standalone against `make run` rather than through pytest's
testcontainers-backed `service` fixture.

Since /v1/decisions/rules/delete now requires a validated bearer token
(api/auth.py's validated_claims dependency), this mints one via the same
token-exchange flow as scripts/test_token_exchange.sh — grant_token_exchange()
must already have been run once against this Keycloak (`make test-token-exchange`
does this), or the exchange step below will fail with "Client not allowed
to exchange".

Usage:
    make up
    make test-token-exchange
    make run &
    python scripts/demo_client.py [--base-url http://localhost:8000] [--keycloak-url http://localhost:8080]

To break in the debugger at the point the token's claims turn into a
Subject (api/routes/_pdp.py's subject_from), set AUTHZ_DEBUG_BREAK=1 on
the server process (e.g. in .vscode/launch.json's env block) before
running this script — see api/routes/_pdp.py's conditional breakpoint().
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from pathlib import Path

import httpx

# clients/ isn't installed as a package — tests get this via pytest's
# pythonpath = ["clients"] (pyproject.toml). Mirror that here so the
# script runs standalone without extra env setup.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients"))

from python.api.operations.get_health import asyncio_detailed as get_health_detailed  # noqa: E402
from python.api.rules.authorize_rule_delete import (
    asyncio_detailed as delete_rule_detailed,  # noqa: E402
)
from python.client import AuthenticatedClient  # noqa: E402
from python.models.context import Context  # noqa: E402
from python.models.did import Did  # noqa: E402
from python.models.rule import Rule  # noqa: E402
from python.models.rule_delete_request import RuleDeleteRequest  # noqa: E402
from python.models.scope import Scope  # noqa: E402
from python.models.subject import Subject  # noqa: E402
from python.models.subject_type import SubjectType  # noqa: E402


def _decode(jwt: str) -> dict:
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


async def _mint_bearer_token(keycloak_url: str, audience: str) -> str:
    """User token for randomaccount, exchanged for audience=authz-service —
    same two-step flow as scripts/test_token_exchange.sh, factored out here
    so this script needs no separate `curl`/bash dependency."""
    token_url = f"{keycloak_url}/realms/rucio/protocol/openid-connect/token"
    async with httpx.AsyncClient() as http:
        user_resp = await http.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "rucio",
                "client_secret": "rucio-secret",
                "username": "randomaccount",
                "password": "secret",
                "scope": "openid",
            },
        )
        user_resp.raise_for_status()
        user_token = user_resp.json()["access_token"]

        exchange_resp = await http.post(
            token_url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": "rucio",
                "client_secret": "rucio-secret",
                "subject_token": user_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": audience,
                "scope": "pep:rucio",
            },
        )
        exchange_resp.raise_for_status()
        return exchange_resp.json()["access_token"]


async def main(base_url: str, keycloak_url: str) -> int:
    token = await _mint_bearer_token(keycloak_url, audience="authz-service")
    claims = _decode(token)
    print(
        f"Bearer token sub={claims.get('sub')} act.sub={claims.get('act', {}).get('sub', 'ABSENT')}"
    )
    print(f"  scope={claims.get('scope')!r}")

    async with AuthenticatedClient(base_url=base_url, token=token) as client:
        health = await get_health_detailed(client=client)
        print(f"GET /healthz -> {health.status_code}: {health.parsed}")
        if health.status_code != 200:
            return 1

        # Owner-deletes-own-rule: the exercisable non-root vector until
        # api/routes/_pdp.py's subject_from reads real entitlements from
        # the token — see test_client_e2e.py's module docstring.
        body = RuleDeleteRequest(
            subject=Subject(type_=SubjectType.OIDC_SUBJECT, id="randomaccount"),
            rule=Rule(
                id="1f0e3dad99908345f7439f8ffabdffc4",
                owner="randomaccount",
                target=Did(scope=Scope(name="test", owner="randomaccount"), name="file1"),
            ),
            context=Context(vo="def"),
        )
        decision = await delete_rule_detailed(client=client, body=body)
        print(f"POST /v1/decisions/rules/delete -> {decision.status_code}: {decision.parsed}")
        return 0 if decision.status_code == 200 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--keycloak-url", default="http://localhost:8080")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.base_url, args.keycloak_url)))

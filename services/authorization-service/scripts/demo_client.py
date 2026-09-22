#!/usr/bin/env python
"""Manual smoke test against a running authz-service, using the generated
client (clients/python) — the same way tests/integration/test_client_e2e.py
does, but standalone against `make run` rather than through pytest's
testcontainers-backed `service` fixture.

Usage:
    docker compose up -d opa opa-init
    export AUTHZ_OPA_URL=http://localhost:8181
    make run &
    python scripts/demo_client.py [--base-url http://localhost:8000]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# clients/ isn't installed as a package — tests get this via pytest's
# pythonpath = ["clients"] (pyproject.toml). Mirror that here so the
# script runs standalone without extra env setup.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients"))

from python.api.operations.get_health import asyncio_detailed as get_health_detailed  # noqa: E402
from python.api.rules.authorize_rule_delete import (
    asyncio_detailed as delete_rule_detailed,  # noqa: E402
)
from python.client import Client  # noqa: E402
from python.models.context import Context  # noqa: E402
from python.models.did import Did  # noqa: E402
from python.models.rule import Rule  # noqa: E402
from python.models.rule_delete_request import RuleDeleteRequest  # noqa: E402
from python.models.scope import Scope  # noqa: E402
from python.models.subject import Subject  # noqa: E402
from python.models.subject_type import SubjectType  # noqa: E402


async def main(base_url: str) -> int:
    async with Client(base_url=base_url) as client:
        health = await get_health_detailed(client=client)
        print(f"GET /healthz -> {health.status_code}: {health.parsed}")
        if health.status_code != 200:
            return 1

        # Owner-deletes-own-rule: the exercisable non-root vector until
        # api/auth.py lands (claims={} in _pdp.py — see test_client_e2e.py's
        # module docstring for why root/self-owned are the only live paths).
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
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.base_url)))

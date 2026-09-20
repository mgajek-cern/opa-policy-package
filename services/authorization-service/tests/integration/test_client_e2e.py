"""End-to-end: the generated client (clients/python) against the real
running service and a real OPA — the one layer nothing else in the
suite touches. tests/integration/test_evaluate.py checks
OpaPolicyDecisionPoint directly; tests/unit/test_routes_registered.py
checks routing with raw httpx bodies. This checks that the
independently-generated client and server models actually agree on
wire format, which neither of those can.

Fixture name is `generated_client` (not `client`) to avoid colliding
with conftest.py's existing httpx.Client fixture used by test_health.py.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from python.api.rules.authorize_rule_create import asyncio_detailed as create_rule_detailed
from python.api.rules.authorize_rule_delete import asyncio_detailed as delete_rule_detailed
from python.client import Client
from python.models.context import Context
from python.models.did import Did
from python.models.rule import Rule
from python.models.rule_create_request import RuleCreateRequest
from python.models.rule_create_request_rule import RuleCreateRequestRule
from python.models.rule_delete_request import RuleDeleteRequest
from python.models.scope import Scope
from python.models.subject import Subject
from python.models.subject_type import SubjectType

RULE_ID = "1f0e3dad99908345f7439f8ffabdffc4"


@pytest.fixture
def generated_client(service: str) -> Iterator[Client]:
    with Client(base_url=service) as generated_client:
        yield generated_client


def _subject(account: str) -> Subject:
    return Subject(type_=SubjectType.OIDC_SUBJECT, id=account)


async def test_owner_may_delete_own_rule_via_generated_client(generated_client: Client) -> None:
    body = RuleDeleteRequest(
        subject=_subject("randomaccount"),
        rule=Rule(
            id=RULE_ID,
            owner="randomaccount",
            target=Did(scope=Scope(name="test", owner="randomaccount"), name="file1"),
        ),
        context=Context(vo="def"),
    )

    response = await delete_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_non_owner_denied_via_generated_client(generated_client: Client) -> None:
    body = RuleDeleteRequest(
        subject=_subject("mallory"),
        rule=Rule(
            id=RULE_ID,
            owner="randomaccount",
            target=Did(scope=Scope(name="test", owner="randomaccount"), name="file1"),
        ),
        context=Context(vo="def"),
    )

    response = await delete_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_parked_operation_via_generated_client_is_501_problem(
    generated_client: Client,
) -> None:
    body = RuleCreateRequest(
        subject=_subject("randomaccount"),
        rule=RuleCreateRequestRule(
            owner="randomaccount",
            locked=False,
            dids=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
        ),
        context=Context(vo="def"),
    )

    response = await create_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 501
    assert response.headers["content-type"] == "application/problem+json"

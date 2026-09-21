"""End-to-end: the generated client (clients/python) against the real
running service and a real OPA — the one layer nothing else in the
suite touches. tests/integration/test_evaluate.py checks
OpaPolicyDecisionPoint directly; tests/unit/test_routes_registered.py
checks routing with raw httpx bodies. This checks that the
independently-generated client and server models actually agree on
wire format, which neither of those can.

Root-privileged vectors (subject id "root") are the only privilege-path
coverage available here: authz.rego's _is_privileged grants root
unconditionally (input.issuer == "root"), needing no token claims —
every other privilege path is unreachable until api/auth.py lands
(rules.py's/dids.py's claims={} TODO, in api/routes/_pdp.py).

Fixture name is `generated_client` (not `client`) to avoid colliding
with conftest.py's existing httpx.Client fixture used by test_health.py.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from python.api.dids.authorize_did_attach import asyncio_detailed as attach_did_detailed
from python.api.dids.authorize_did_create import asyncio_detailed as create_did_detailed
from python.api.dids.authorize_did_detach import asyncio_detailed as detach_did_detailed
from python.api.rses.authorize_rse_create import asyncio_detailed as create_rse_detailed
from python.api.rules.authorize_rule_create import asyncio_detailed as create_rule_detailed
from python.api.rules.authorize_rule_delete import asyncio_detailed as delete_rule_detailed
from python.api.rules.authorize_rule_update import asyncio_detailed as update_rule_detailed
from python.client import Client
from python.models.context import Context
from python.models.did import Did
from python.models.did_attach_request import DidAttachRequest
from python.models.did_attach_request_attachments_item import DidAttachRequestAttachmentsItem
from python.models.did_create_request import DidCreateRequest
from python.models.did_detach_request import DidDetachRequest
from python.models.rse import Rse
from python.models.rse_create_request import RseCreateRequest
from python.models.rule import Rule
from python.models.rule_create_request import RuleCreateRequest
from python.models.rule_create_request_rule import RuleCreateRequestRule
from python.models.rule_delete_request import RuleDeleteRequest
from python.models.rule_update_request import RuleUpdateRequest
from python.models.rule_update_request_changes import RuleUpdateRequestChanges
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


def _root() -> Subject:
    return Subject(type_=SubjectType.RUCIO_ACCOUNT, id="root")


# rules/delete


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


# rules/create


async def test_owner_may_create_rule_over_owned_dids_via_generated_client(
    generated_client: Client,
) -> None:
    body = RuleCreateRequest(
        subject=_subject("randomaccount"),
        rule=RuleCreateRequestRule(
            owner="randomaccount",
            locked=False,
            dids=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
            rse_expression="CERN_DATADISK",
        ),
        context=Context(vo="def"),
    )

    response = await create_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_owner_denied_rule_over_foreign_dids_via_generated_client(
    generated_client: Client,
) -> None:
    body = RuleCreateRequest(
        subject=_subject("randomaccount"),
        rule=RuleCreateRequestRule(
            owner="randomaccount",
            locked=False,
            dids=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
            rse_expression="CERN_DATADISK",
        ),
        context=Context(vo="def"),
    )

    response = await create_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_root_may_create_rule_over_foreign_dids_via_generated_client(
    generated_client: Client,
) -> None:
    body = RuleCreateRequest(
        subject=_root(),
        rule=RuleCreateRequestRule(
            owner="root",
            locked=False,
            dids=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
            rse_expression="CERN_DATADISK",
        ),
        context=Context(vo="def"),
    )

    response = await create_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# rules/update


async def test_owner_may_update_own_rule_within_owned_scope_via_generated_client(
    generated_client: Client,
) -> None:
    body = RuleUpdateRequest(
        subject=_subject("randomaccount"),
        rule=Rule(
            id=RULE_ID,
            owner="randomaccount",
            target=Did(scope=Scope(name="test", owner="randomaccount"), name="file1"),
        ),
        changes=RuleUpdateRequestChanges(lifetime=3600),
        context=Context(vo="def"),
    )

    response = await update_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_owner_denied_update_when_target_scope_unowned_via_generated_client(
    generated_client: Client,
) -> None:
    body = RuleUpdateRequest(
        subject=_subject("randomaccount"),
        rule=Rule(
            id=RULE_ID,
            owner="randomaccount",
            target=Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1"),
        ),
        changes=RuleUpdateRequestChanges(lifetime=3600),
        context=Context(vo="def"),
    )

    response = await update_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_reassignment_denied_for_owner_via_generated_client(
    generated_client: Client,
) -> None:
    body = RuleUpdateRequest(
        subject=_subject("randomaccount"),
        rule=Rule(
            id=RULE_ID,
            owner="randomaccount",
            target=Did(scope=Scope(name="test", owner="randomaccount"), name="file1"),
        ),
        changes=RuleUpdateRequestChanges(owner="ddmlab"),
        context=Context(vo="def"),
    )

    response = await update_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_root_may_reassign_any_rule_via_generated_client(generated_client: Client) -> None:
    body = RuleUpdateRequest(
        subject=_root(),
        rule=Rule(
            id=RULE_ID,
            owner="randomaccount",
            target=Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1"),
        ),
        changes=RuleUpdateRequestChanges(owner="ddmlab"),
        context=Context(vo="def"),
    )

    response = await update_rule_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# dids/create


async def test_owner_may_create_dids_in_owned_scope_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidCreateRequest(
        subject=_subject("randomaccount"),
        dids=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
        context=Context(vo="def"),
    )

    response = await create_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_owner_denied_creating_dids_in_foreign_scope_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidCreateRequest(
        subject=_subject("randomaccount"),
        dids=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
        context=Context(vo="def"),
    )

    response = await create_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_root_may_create_dids_in_any_scope_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidCreateRequest(
        subject=_root(),
        dids=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
        context=Context(vo="def"),
    )

    response = await create_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# dids/attach


async def test_owner_may_attach_to_owned_parent_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidAttachRequest(
        subject=_subject("randomaccount"),
        attachments=[
            DidAttachRequestAttachmentsItem(
                parent=Did(scope=Scope(name="test", owner="randomaccount"), name="container1"),
                children=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
            )
        ],
        context=Context(vo="def"),
    )

    response = await attach_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_owner_denied_attach_to_foreign_parent_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidAttachRequest(
        subject=_subject("randomaccount"),
        attachments=[
            DidAttachRequestAttachmentsItem(
                parent=Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="container1"),
                children=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
            )
        ],
        context=Context(vo="def"),
    )

    response = await attach_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_root_may_attach_to_any_parent_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidAttachRequest(
        subject=_root(),
        attachments=[
            DidAttachRequestAttachmentsItem(
                parent=Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="container1"),
                children=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
            )
        ],
        context=Context(vo="def"),
    )

    response = await attach_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# dids/detach


async def test_owner_may_detach_from_owned_parent_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidDetachRequest(
        subject=_subject("randomaccount"),
        parent=Did(scope=Scope(name="test", owner="randomaccount"), name="container1"),
        children=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
        context=Context(vo="def"),
    )

    response = await detach_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_owner_denied_detach_from_foreign_parent_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidDetachRequest(
        subject=_subject("randomaccount"),
        parent=Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="container1"),
        children=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
        context=Context(vo="def"),
    )

    response = await detach_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_root_may_detach_from_any_parent_via_generated_client(
    generated_client: Client,
) -> None:
    body = DidDetachRequest(
        subject=_root(),
        parent=Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="container1"),
        children=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
        context=Context(vo="def"),
    )

    response = await detach_did_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# still parked (rses/create)


async def test_parked_operation_via_generated_client_is_501_problem(
    generated_client: Client,
) -> None:
    body = RseCreateRequest(
        subject=_subject("randomaccount"), rse=Rse(name="CERN_DATADISK"), context=Context(vo="def")
    )

    response = await create_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 501
    assert response.headers["content-type"] == "application/problem+json"

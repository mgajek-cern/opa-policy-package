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
from python.api.privileged.authorize_privileged_operation import (
    asyncio_detailed as create_privileged_operation_detailed,
)
from python.api.protocols.authorize_protocol_create import (
    asyncio_detailed as create_protocol_detailed,
)
from python.api.protocols.authorize_protocol_delete import (
    asyncio_detailed as delete_protocol_detailed,
)
from python.api.protocols.authorize_protocol_update import (
    asyncio_detailed as update_protocol_detailed,
)
from python.api.replicas.authorize_replica_delete import asyncio_detailed as delete_replica_detailed
from python.api.replicas.authorize_replica_register import (
    asyncio_detailed as register_replica_detailed,
)
from python.api.rses.authorize_rse_attribute_delete import (
    asyncio_detailed as delete_rse_attribute_detailed,
)
from python.api.rses.authorize_rse_attribute_set import (
    asyncio_detailed as set_rse_attribute_detailed,
)
from python.api.rses.authorize_rse_create import asyncio_detailed as create_rse_detailed
from python.api.rses.authorize_rse_delete import asyncio_detailed as delete_rse_detailed
from python.api.rses.authorize_rse_update import asyncio_detailed as update_rse_detailed
from python.api.rules.authorize_rule_create import asyncio_detailed as create_rule_detailed
from python.api.rules.authorize_rule_delete import asyncio_detailed as delete_rule_detailed
from python.api.rules.authorize_rule_update import asyncio_detailed as update_rule_detailed
from python.client import AuthenticatedClient
from python.models.context import Context
from python.models.did import Did
from python.models.did_attach_request import DidAttachRequest
from python.models.did_attach_request_attachments_item import DidAttachRequestAttachmentsItem
from python.models.did_create_request import DidCreateRequest
from python.models.did_detach_request import DidDetachRequest
from python.models.privileged_operation_request import PrivilegedOperationRequest
from python.models.protocol import Protocol
from python.models.protocol_create_request import ProtocolCreateRequest
from python.models.protocol_delete_request import ProtocolDeleteRequest
from python.models.protocol_update_request import ProtocolUpdateRequest
from python.models.replica_delete_request import ReplicaDeleteRequest
from python.models.replica_register_request import ReplicaRegisterRequest
from python.models.rse import Rse
from python.models.rse_attribute_delete_request import RseAttributeDeleteRequest
from python.models.rse_attribute_delete_request_attribute import RseAttributeDeleteRequestAttribute
from python.models.rse_attribute_set_request import RseAttributeSetRequest
from python.models.rse_attribute_set_request_attribute import RseAttributeSetRequestAttribute
from python.models.rse_create_request import RseCreateRequest
from python.models.rse_delete_request import RseDeleteRequest
from python.models.rse_update_request import RseUpdateRequest
from python.models.rse_update_request_changes import RseUpdateRequestChanges
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
def generated_client(service: str, bearer_token: str) -> Iterator[AuthenticatedClient]:
    with AuthenticatedClient(base_url=service, token=bearer_token) as generated_client:
        yield generated_client


def _subject(account: str) -> Subject:
    return Subject(type_=SubjectType.OIDC_SUBJECT, id=account)


def _root() -> Subject:
    return Subject(type_=SubjectType.RUCIO_ACCOUNT, id="root")


# rules/delete


async def test_owner_may_delete_own_rule_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
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


async def test_non_owner_denied_via_generated_client(generated_client: AuthenticatedClient) -> None:
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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


async def test_root_may_reassign_any_rule_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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
    generated_client: AuthenticatedClient,
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


# rses/create


async def test_root_may_create_rse_with_valid_name_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseCreateRequest(
        subject=_root(), rse=Rse(name="CERN_DATADISK"), context=Context(vo="def")
    )

    response = await create_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_root_denied_create_rse_with_invalid_name_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    """Privilege alone isn't enough: _perm_add_rse also requires
    _rse_name_valid, checked inside the Rego regardless of caller."""
    body = RseCreateRequest(
        subject=_root(), rse=Rse(name="not-a-valid-name"), context=Context(vo="def")
    )

    response = await create_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_non_root_denied_create_rse_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    """No entitlement claims are extracted yet (claims={} TODO), so
    only root's unconditional bootstrap can pass _is_privileged."""
    body = RseCreateRequest(
        subject=_subject("randomaccount"), rse=Rse(name="CERN_DATADISK"), context=Context(vo="def")
    )

    response = await create_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


# rses/update


async def test_root_may_update_rse_without_rename_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseUpdateRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        changes=RseUpdateRequestChanges(),
        context=Context(vo="def"),
    )

    response = await update_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_root_denied_rename_to_invalid_name_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseUpdateRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        changes=RseUpdateRequestChanges(name="not-a-valid-name"),
        context=Context(vo="def"),
    )

    response = await update_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


# rses/delete


async def test_root_may_delete_rse_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseDeleteRequest(
        subject=_root(), rse=Rse(name="CERN_DATADISK"), context=Context(vo="def")
    )

    response = await delete_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_non_root_denied_delete_rse_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseDeleteRequest(
        subject=_subject("randomaccount"), rse=Rse(name="CERN_DATADISK"), context=Context(vo="def")
    )

    response = await delete_rse_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


# rses/attributes/set, rses/attributes/delete


async def test_root_may_set_rse_attribute_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseAttributeSetRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        attribute=RseAttributeSetRequestAttribute(key="fts"),
        context=Context(vo="def"),
    )

    response = await set_rse_attribute_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_root_may_delete_rse_attribute_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = RseAttributeDeleteRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        attribute=RseAttributeDeleteRequestAttribute(key="fts"),
        context=Context(vo="def"),
    )

    response = await delete_rse_attribute_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# protocols/create, update, delete


async def test_root_may_add_protocol_with_allowed_scheme_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = ProtocolCreateRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        protocol=Protocol(scheme="davs"),
        context=Context(vo="def"),
    )

    response = await create_protocol_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_root_denied_add_protocol_with_disallowed_scheme_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    """Privilege alone isn't enough: _protocol_scheme_allowed applies
    even to root."""
    body = ProtocolCreateRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        protocol=Protocol(scheme="ftp"),
        context=Context(vo="def"),
    )

    response = await create_protocol_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_non_root_denied_add_protocol_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    """No entitlement claims are extracted yet (claims={} TODO), so
    only root's unconditional bootstrap can pass _is_privileged."""
    body = ProtocolCreateRequest(
        subject=_subject("randomaccount"),
        rse=Rse(name="CERN_DATADISK"),
        protocol=Protocol(scheme="davs"),
        context=Context(vo="def"),
    )

    response = await create_protocol_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False


async def test_root_may_update_protocol_without_scheme_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = ProtocolUpdateRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        protocol=Protocol(),
        context=Context(vo="def"),
    )

    response = await update_protocol_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_root_may_delete_protocol_without_scheme_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    """del_protocol commonly carries no scheme; absent scheme always
    passes _protocol_scheme_allowed."""
    body = ProtocolDeleteRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        protocol=Protocol(),
        context=Context(vo="def"),
    )

    response = await delete_protocol_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# replicas/register, delete
#
# randomaccount holds the rucio-users entitlement (realm.json), which
# authz.rego's hardcoded fallback maps to the "user" privilege level
# (_entitlement_privilege). _perm_add_replicas'/_perm_delete_replicas'
# user-tier branches grant on privilege level + valid RSE name (add
# only) + ownership of every file's scope — all satisfied below, since
# ReplicaRegisterRequest/ReplicaDeleteRequest carry `files` directly
# per the contract (unlike the Rucio-gateway path this Rego's replicas
# comment block separately warns about).


async def test_root_may_register_replicas_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = ReplicaRegisterRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        files=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
        context=Context(vo="def"),
    )

    response = await register_replica_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_entitled_user_may_register_replicas_over_owned_scope_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = ReplicaRegisterRequest(
        subject=_subject("randomaccount"),
        rse=Rse(name="CERN_DATADISK"),
        files=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
        context=Context(vo="def"),
    )

    response = await register_replica_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_root_may_delete_replicas_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = ReplicaDeleteRequest(
        subject=_root(),
        rse=Rse(name="CERN_DATADISK"),
        files=[Did(scope=Scope(name="ddmlab", owner="ddmlab"), name="file1")],
        context=Context(vo="def"),
    )

    response = await delete_replica_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_entitled_user_may_delete_replicas_over_owned_scope_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = ReplicaDeleteRequest(
        subject=_subject("randomaccount"),
        rse=Rse(name="CERN_DATADISK"),
        files=[Did(scope=Scope(name="test", owner="randomaccount"), name="file1")],
        context=Context(vo="def"),
    )

    response = await delete_replica_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


# privileged-operations — the last route


async def test_root_may_perform_any_privileged_operation_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = PrivilegedOperationRequest(
        subject=_root(), operation="add_account", context=Context(vo="def")
    )

    response = await create_privileged_operation_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is True


async def test_non_root_denied_privileged_operation_via_generated_client(
    generated_client: AuthenticatedClient,
) -> None:
    body = PrivilegedOperationRequest(
        subject=_subject("randomaccount"), operation="add_account", context=Context(vo="def")
    )

    response = await create_privileged_operation_detailed(client=generated_client, body=body)

    assert response.status_code == 200
    assert response.parsed is not None
    assert response.parsed.decision is False

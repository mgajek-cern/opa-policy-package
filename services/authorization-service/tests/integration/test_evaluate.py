"""OpaPolicyDecisionPoint.evaluate() against a real OPA (authoritative, design-006 Testing).

Exercises translate.py's round trip end to end: Evaluation -> OPA input ->
real policy evaluation -> Outcome.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from authz_service.adapters.pdp.opa import OpaPolicyDecisionPoint
from authz_service.core.model import Evaluation, Outcome, Resource, Subject


@pytest.fixture
async def opa_pdp(pdp: str) -> AsyncIterator[OpaPolicyDecisionPoint]:
    adapter = OpaPolicyDecisionPoint(url=pdp, policy_path="vo/authz/v5/allow", timeout_seconds=5.0)
    yield adapter
    await adapter.aclose()


def _rule_delete(*, subject_id: str, rule_owner: str, scope: str, scope_owner: str) -> Evaluation:
    return Evaluation(
        operation="del_rule",
        subject=Subject(type="oidc_subject", id=subject_id, claims={}),
        resources=(
            Resource(
                type="rule",
                id="rule-1",
                owner=rule_owner,
                attributes={"scope": scope, "scope_owner": scope_owner},
            ),
        ),
    )


async def test_owner_may_delete_own_rule(opa_pdp: OpaPolicyDecisionPoint) -> None:
    evaluation = _rule_delete(
        subject_id="alice@example.org",
        rule_owner="alice@example.org",
        scope="test",
        scope_owner="alice@example.org",
    )
    assert await opa_pdp.evaluate(evaluation) is Outcome.PERMIT


async def test_non_owner_may_not_delete_rule(opa_pdp: OpaPolicyDecisionPoint) -> None:
    evaluation = _rule_delete(
        subject_id="mallory@example.org",
        rule_owner="alice@example.org",
        scope="test",
        scope_owner="alice@example.org",
    )
    assert await opa_pdp.evaluate(evaluation) is Outcome.DENY


async def test_unreachable_opa_is_indeterminate() -> None:
    adapter = OpaPolicyDecisionPoint(
        url="http://127.0.0.1:1", policy_path="vo/authz/v5/allow", timeout_seconds=0.5
    )
    try:
        evaluation = _rule_delete(
            subject_id="alice@example.org",
            rule_owner="alice@example.org",
            scope="test",
            scope_owner="alice@example.org",
        )
        assert await adapter.evaluate(evaluation) is Outcome.INDETERMINATE
    finally:
        await adapter.aclose()

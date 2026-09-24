"""Outcome classification: pure logic, so a unit test is allowed (ADR-004)."""

import pytest

from authz_service.core.model import Outcome, grants, http_status_for


@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (Outcome.PERMIT, 200),
        (Outcome.DENY, 200),
        (Outcome.NOT_APPLICABLE, 500),
        (Outcome.INDETERMINATE, 503),
    ],
)
def test_status_per_outcome(outcome: Outcome, status: int) -> None:
    assert http_status_for(outcome) == status


def test_only_permit_grants() -> None:
    """Invariant 1, at the level a unit test can reach."""
    assert grants(Outcome.PERMIT)
    assert not any(grants(o) for o in Outcome if o is not Outcome.PERMIT)


def test_every_outcome_has_a_status() -> None:
    for outcome in Outcome:
        assert http_status_for(outcome) in (200, 500, 503)

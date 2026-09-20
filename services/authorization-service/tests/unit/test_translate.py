"""Evaluation -> OPA input, and OPA response -> Outcome (pure logic, ADR-004)."""

from __future__ import annotations

import pytest

from authz_service.adapters.pdp.opa import translate
from authz_service.core.model import Evaluation, Outcome, Resource, Subject


def _subject(**claims: object) -> Subject:
    return Subject(type="oidc_subject", id="alice@example.org", claims=claims)


def _rule_delete(subject: Subject, *, rule_owner: str, scope: str, scope_owner: str) -> Evaluation:
    return Evaluation(
        operation="del_rule",
        subject=subject,
        resources=(
            Resource(
                type="rule",
                id="rule-1",
                owner=rule_owner,
                attributes={"scope": scope, "scope_owner": scope_owner},
            ),
        ),
    )


class TestToken:
    def test_forwards_allowlisted_claims_only(self) -> None:
        subject = _subject(
            entitlements=["urn:mace:egi.eu:group:vo.example"],
            acr="loa3",
            iss="https://issuer.example.org",
            sub="abc123",
            jti="req-1",
            extra="should not be forwarded",
        )
        evaluation = _rule_delete(
            subject, rule_owner="alice@example.org", scope="test", scope_owner="alice@example.org"
        )
        token = translate.to_opa_input(evaluation)["token"]
        assert token["entitlements"] == ["urn:mace:egi.eu:group:vo.example"]
        assert token["acr"] == "loa3"
        assert token["iss"] == "https://issuer.example.org"
        assert token["sub"] == "abc123"
        assert token["jti"] == "req-1"
        assert "extra" not in token

    def test_omits_absent_claims(self) -> None:
        evaluation = _rule_delete(
            _subject(),
            rule_owner="alice@example.org",
            scope="test",
            scope_owner="alice@example.org",
        )
        assert translate.to_opa_input(evaluation)["token"] == {}


class TestDelRuleKwargs:
    def test_owned_scope_is_reported(self) -> None:
        subject = Subject(type="oidc_subject", id="alice@example.org", claims={})
        evaluation = _rule_delete(
            subject, rule_owner="bob@example.org", scope="test", scope_owner="alice@example.org"
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs["rule_id"] == "rule-1"
        assert kwargs["rule_owner"] == "bob@example.org"
        assert kwargs["rule_scope"] == "test"
        assert kwargs["owned_scopes"] == ["test"]

    def test_scope_not_owned_by_subject_is_excluded(self) -> None:
        subject = Subject(type="oidc_subject", id="alice@example.org", claims={})
        evaluation = _rule_delete(
            subject, rule_owner="bob@example.org", scope="test", scope_owner="bob@example.org"
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs["owned_scopes"] == []


class TestUnsupportedOperation:
    def test_raises_for_unregistered_action(self) -> None:
        evaluation = Evaluation(operation="add_rule", subject=_subject(), resources=())
        with pytest.raises(ValueError, match="add_rule"):
            translate.to_opa_input(evaluation)


class TestOutcomeFromResponse:
    @pytest.mark.parametrize(
        ("status_code", "body", "expected"),
        [
            (200, {"result": True}, Outcome.PERMIT),
            (200, {"result": False}, Outcome.DENY),
            (200, {}, Outcome.NOT_APPLICABLE),  # OPA's undefined-rule shape
            (200, {"result": "not-a-bool"}, Outcome.INDETERMINATE),
            (200, [], Outcome.INDETERMINATE),  # not a dict at all
            (500, {"result": True}, Outcome.INDETERMINATE),
            (503, {}, Outcome.INDETERMINATE),
        ],
    )
    def test_classification(self, status_code: int, body: object, expected: Outcome) -> None:
        assert translate.outcome_from_response(status_code, body) is expected

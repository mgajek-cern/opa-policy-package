"""Evaluation -> OPA input, and OPA response -> Outcome (pure logic, ADR-004)."""

from __future__ import annotations

import pytest

from authz_service.adapters.pdp.opa import translate
from authz_service.core.model import Evaluation, Outcome, Resource, Subject


def _subject(**claims: object) -> Subject:
    return Subject(type="oidc_subject", id="randomaccount", claims=claims)


def _rule_delete(subject: Subject, *, rule_owner: str) -> Evaluation:
    return Evaluation(
        operation="del_rule",
        subject=subject,
        resources=(Resource(type="rule", id="rule-1", owner=rule_owner),),
    )


class TestToken:
    def test_forwards_allowlisted_claims_only(self) -> None:
        subject = _subject(
            entitlements=["urn:example:aai.example.org:group:rucio-users:role=member"],
            acr="loa3",
            iss="https://issuer.example.org",
            sub="abc123",
            jti="req-1",
            extra="should not be forwarded",
        )
        evaluation = _rule_delete(subject, rule_owner="randomaccount")
        token = translate.to_opa_input(evaluation)["token"]
        assert token["entitlements"] == [
            "urn:example:aai.example.org:group:rucio-users:role=member"
        ]
        assert token["acr"] == "loa3"
        assert token["sub"] == "abc123"
        assert "extra" not in token

    def test_omits_absent_claims(self) -> None:
        evaluation = _rule_delete(_subject(), rule_owner="randomaccount")
        assert translate.to_opa_input(evaluation)["token"] == {}


class TestDelRuleKwargs:
    def test_kwargs_carry_only_rule_id_and_owner(self) -> None:
        evaluation = _rule_delete(_subject(), rule_owner="randomaccount")
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"rule_id": "rule-1", "rule_owner": "randomaccount"}


class TestAddRuleKwargs:
    def _evaluation(self, **context: object) -> Evaluation:
        return Evaluation(
            operation="add_rule",
            subject=_subject(),
            resources=(
                Resource(type="did", id="f1", owner="randomaccount", attributes={"scope": "test"}),
                Resource(type="did", id="f2", owner="ddmlab", attributes={"scope": "ddmlab"}),
            ),
            context={"account": "randomaccount", "locked": False, **context},
        )

    def test_owned_scopes_are_the_subset_the_subject_owns(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation())["kwargs"]
        assert kwargs["dids"] == [
            {"scope": "test", "name": "f1"},
            {"scope": "ddmlab", "name": "f2"},
        ]
        assert kwargs["owned_scopes"] == ["test"]
        assert kwargs["account"] == "randomaccount"
        assert kwargs["locked"] is False

    def test_rse_expression_omitted_when_absent(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation())["kwargs"]
        assert "rse_expression" not in kwargs
        assert "source_rse_expression" not in kwargs

    def test_rse_expression_included_when_present(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation(rse_expression="CERN_DATADISK"))["kwargs"]
        assert kwargs["rse_expression"] == "CERN_DATADISK"


class TestUpdateRuleKwargs:
    def _evaluation(self, *, scope_owner: str, **changes: object) -> Evaluation:
        return Evaluation(
            operation="update_rule",
            subject=_subject(),
            resources=(
                Resource(
                    type="rule",
                    id="rule-1",
                    owner="randomaccount",
                    attributes={"scope": "test", "scope_owner": scope_owner},
                ),
            ),
            context={
                "changes": {"owner": None, "lifetime": None, "rse_expression": None, **changes}
            },
        )

    def test_owned_target_scope_included(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation(scope_owner="randomaccount"))["kwargs"]
        assert kwargs["rule_scope"] == "test"
        assert kwargs["owned_scopes"] == ["test"]
        assert "options" not in kwargs

    def test_unowned_target_scope_excluded(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation(scope_owner="ddmlab"))["kwargs"]
        assert kwargs["owned_scopes"] == []

    def test_reassignment_sends_options_even_to_same_owner(self) -> None:
        """owner present with any non-null value is a reassignment,
        including reassignment to the current owner (design-005)."""
        kwargs = translate.to_opa_input(
            self._evaluation(scope_owner="randomaccount", owner="randomaccount")
        )["kwargs"]
        assert kwargs["options"] == {"account": "randomaccount"}

    def test_no_options_key_when_owner_not_in_changes(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation(scope_owner="randomaccount"))["kwargs"]
        assert "options" not in kwargs


class TestAddDidsKwargs:
    def test_only_owned_scope_is_reported(self) -> None:
        evaluation = Evaluation(
            operation="add_dids",
            subject=_subject(),
            resources=(
                Resource(type="did", id="f1", owner="randomaccount", attributes={"scope": "test"}),
                Resource(type="did", id="f2", owner="ddmlab", attributes={"scope": "ddmlab"}),
            ),
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs["dids"] == [
            {"scope": "test", "name": "f1"},
            {"scope": "ddmlab", "name": "f2"},
        ]
        assert kwargs["owned_scopes"] == ["test"]


class TestAttachDidsToDidsKwargs:
    def test_owned_and_unowned_parent_scopes(self) -> None:
        evaluation = Evaluation(
            operation="attach_dids_to_dids",
            subject=_subject(),
            resources=(
                Resource(
                    type="did", id="container1", owner="randomaccount", attributes={"scope": "test"}
                ),
                Resource(
                    type="did", id="container2", owner="ddmlab", attributes={"scope": "ddmlab"}
                ),
            ),
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs["attachments"] == [
            {"scope": "test", "name": "container1"},
            {"scope": "ddmlab", "name": "container2"},
        ]
        assert kwargs["owned_scopes"] == ["test"]


class TestDetachDidsKwargs:
    def test_owned_parent_scope(self) -> None:
        evaluation = Evaluation(
            operation="detach_dids",
            subject=_subject(),
            resources=(
                Resource(
                    type="did", id="container1", owner="randomaccount", attributes={"scope": "test"}
                ),
            ),
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"scope": "test", "owned_scopes": ["test"]}

    def test_unowned_parent_scope(self) -> None:
        evaluation = Evaluation(
            operation="detach_dids",
            subject=_subject(),
            resources=(
                Resource(
                    type="did", id="container1", owner="ddmlab", attributes={"scope": "ddmlab"}
                ),
            ),
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"scope": "ddmlab", "owned_scopes": []}


class TestUnsupportedOperation:
    def test_raises_for_unregistered_action(self) -> None:
        evaluation = Evaluation(operation="del_rse", subject=_subject(), resources=())
        with pytest.raises(ValueError, match="del_rse"):
            translate.to_opa_input(evaluation)


class TestOutcomeFromResponse:
    @pytest.mark.parametrize(
        ("status_code", "body", "expected"),
        [
            (200, {"result": True}, Outcome.PERMIT),
            (200, {"result": False}, Outcome.DENY),
            (200, {}, Outcome.NOT_APPLICABLE),
            (200, {"result": "not-a-bool"}, Outcome.INDETERMINATE),
            (200, [], Outcome.INDETERMINATE),
            (500, {"result": True}, Outcome.INDETERMINATE),
            (503, {}, Outcome.INDETERMINATE),
        ],
    )
    def test_classification(self, status_code: int, body: object, expected: Outcome) -> None:
        assert translate.outcome_from_response(status_code, body) is expected

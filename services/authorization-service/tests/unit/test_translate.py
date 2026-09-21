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


class TestAddRseKwargs:
    def test_kwargs_carry_only_the_name(self) -> None:
        evaluation = Evaluation(
            operation="add_rse",
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK"}


class TestUpdateRseKwargs:
    def _evaluation(self, **context: object) -> Evaluation:
        return Evaluation(
            operation="update_rse",
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
            context=context,
        )

    def test_no_rename_sends_empty_parameters(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation())["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK", "parameters": {}}

    def test_rename_sends_new_name(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation(new_name="CERN_TAPE"))["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK", "parameters": {"rse": "CERN_TAPE"}}


class TestDelRseKwargs:
    def test_kwargs_carry_only_the_name(self) -> None:
        evaluation = Evaluation(
            operation="del_rse",
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK"}


class TestAddRseAttributeKwargs:
    def test_value_included_when_present(self) -> None:
        evaluation = Evaluation(
            operation="add_rse_attribute",
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
            context={"key": "fts", "value": "https://fts:8446"},
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK", "key": "fts", "value": "https://fts:8446"}

    def test_value_omitted_when_absent(self) -> None:
        evaluation = Evaluation(
            operation="add_rse_attribute",
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
            context={"key": "fts"},
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK", "key": "fts"}


class TestDelRseAttributeKwargs:
    def test_kwargs_carry_rse_and_key(self) -> None:
        evaluation = Evaluation(
            operation="del_rse_attribute",
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
            context={"key": "fts"},
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK", "key": "fts"}


class TestProtocolKwargs:
    def _evaluation(self, operation: str, **context: object) -> Evaluation:
        return Evaluation(
            operation=operation,
            subject=_subject(),
            resources=(Resource(type="rse", id="CERN_DATADISK", owner=None),),
            context=context,
        )

    def test_scheme_included_when_present(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation("add_protocol", scheme="davs"))["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK", "scheme": "davs"}

    def test_scheme_omitted_when_absent(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation("del_protocol"))["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK"}

    def test_scheme_omitted_when_none(self) -> None:
        kwargs = translate.to_opa_input(self._evaluation("update_protocol", scheme=None))["kwargs"]
        assert kwargs == {"rse": "CERN_DATADISK"}

    def test_all_three_actions_share_the_same_builder(self) -> None:
        for operation in ("add_protocol", "update_protocol", "del_protocol"):
            kwargs = translate.to_opa_input(self._evaluation(operation, scheme="davs"))["kwargs"]
            assert kwargs == {"rse": "CERN_DATADISK", "scheme": "davs"}


class TestAddReplicasKwargs:
    def test_owned_files_reported(self) -> None:
        evaluation = Evaluation(
            operation="add_replicas",
            subject=_subject(),
            resources=(
                Resource(type="did", id="f1", owner="randomaccount", attributes={"scope": "test"}),
                Resource(type="did", id="f2", owner="ddmlab", attributes={"scope": "ddmlab"}),
            ),
            context={"rse": "CERN_DATADISK"},
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs["rse"] == "CERN_DATADISK"
        assert kwargs["files"] == [
            {"scope": "test", "name": "f1"},
            {"scope": "ddmlab", "name": "f2"},
        ]
        assert kwargs["owned_scopes"] == ["test"]


class TestDeleteReplicasKwargs:
    def test_owned_files_reported_no_name_check_distinction(self) -> None:
        """Same shape as add_replicas — the Rego's own omission of a
        name check on delete_replicas doesn't change what this module
        forwards; the Rego is what applies or ignores rse."""
        evaluation = Evaluation(
            operation="delete_replicas",
            subject=_subject(),
            resources=(
                Resource(type="did", id="f1", owner="randomaccount", attributes={"scope": "test"}),
            ),
            context={"rse": "cern_bad"},
        )
        kwargs = translate.to_opa_input(evaluation)["kwargs"]
        assert kwargs == {
            "rse": "cern_bad",
            "files": [{"scope": "test", "name": "f1"}],
            "owned_scopes": ["test"],
        }


class TestUnsupportedOperation:
    def test_raises_for_unregistered_action(self) -> None:
        evaluation = Evaluation(
            operation="update_replicas_states", subject=_subject(), resources=()
        )
        with pytest.raises(ValueError, match="update_replicas_states"):
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

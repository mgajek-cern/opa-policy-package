from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.context import Context
    from ..models.rule import Rule
    from ..models.subject import Subject


T = TypeVar("T", bound="RuleDeleteRequest")


@_attrs_define
class RuleDeleteRequest:
    """
    Attributes:
        subject (Subject): The principal the decision is about. Its claims are asserted by the
            authenticated PEP; the service does not re-validate the token (design-005).
        rule (Rule): An existing rule, with the facts the PEP resolved for it.
        context (Context):
    """

    subject: Subject
    rule: Rule
    context: Context
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject = self.subject.to_dict()

        rule = self.rule.to_dict()

        context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject": subject,
                "rule": rule,
                "context": context,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.context import Context  # noqa: PLC0415
        from ..models.rule import Rule  # noqa: PLC0415
        from ..models.subject import Subject  # noqa: PLC0415

        d = dict(src_dict)
        subject = Subject.from_dict(d.pop("subject"))

        rule = Rule.from_dict(d.pop("rule"))

        context = Context.from_dict(d.pop("context"))

        rule_delete_request = cls(
            subject=subject,
            rule=rule,
            context=context,
        )

        rule_delete_request.additional_properties = d
        return rule_delete_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties

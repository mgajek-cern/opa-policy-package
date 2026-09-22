from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.context import Context
    from ..models.subject import Subject


T = TypeVar("T", bound="PrivilegedOperationRequest")


@_attrs_define
class PrivilegedOperationRequest:
    """
    Attributes:
        subject (Subject): The principal the decision is about. type/id name the subject for
            logging, and are the only source of identity for credentials that
            carry no bearer token at all (e.g. the root bootstrap). Where a
            token is present, the claims the policy actually reads
            (entitlements, acr) come from that validated token, not from this
            object — there is no claims payload here to assert.
        operation (str): The consumer's operation name, e.g. add_account. Carries no
            arguments: the policy decides on the subject alone.
        context (Context):
    """

    subject: Subject
    operation: str
    context: Context
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject = self.subject.to_dict()

        operation = self.operation

        context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject": subject,
                "operation": operation,
                "context": context,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.context import Context  # noqa: PLC0415
        from ..models.subject import Subject  # noqa: PLC0415

        d = dict(src_dict)
        subject = Subject.from_dict(d.pop("subject"))

        operation = d.pop("operation")

        context = Context.from_dict(d.pop("context"))

        privileged_operation_request = cls(
            subject=subject,
            operation=operation,
            context=context,
        )

        privileged_operation_request.additional_properties = d
        return privileged_operation_request

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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.context import Context
    from ..models.did_attach_request_attachments_item import DidAttachRequestAttachmentsItem
    from ..models.subject import Subject


T = TypeVar("T", bound="DidAttachRequest")


@_attrs_define
class DidAttachRequest:
    """
    Attributes:
        subject (Subject): The principal the decision is about. Its claims are asserted by the
            authenticated PEP; the service does not re-validate the token (design-005).
        attachments (list[DidAttachRequestAttachmentsItem]):
        context (Context):
    """

    subject: Subject
    attachments: list[DidAttachRequestAttachmentsItem]
    context: Context
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject = self.subject.to_dict()

        attachments = []
        for attachments_item_data in self.attachments:
            attachments_item = attachments_item_data.to_dict()
            attachments.append(attachments_item)

        context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject": subject,
                "attachments": attachments,
                "context": context,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.context import Context  # noqa: PLC0415
        from ..models.did_attach_request_attachments_item import (
            DidAttachRequestAttachmentsItem,  # noqa: PLC0415
        )
        from ..models.subject import Subject  # noqa: PLC0415

        d = dict(src_dict)
        subject = Subject.from_dict(d.pop("subject"))

        attachments = []
        _attachments = d.pop("attachments")
        for attachments_item_data in _attachments:
            attachments_item = DidAttachRequestAttachmentsItem.from_dict(attachments_item_data)

            attachments.append(attachments_item)

        context = Context.from_dict(d.pop("context"))

        did_attach_request = cls(
            subject=subject,
            attachments=attachments,
            context=context,
        )

        did_attach_request.additional_properties = d
        return did_attach_request

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

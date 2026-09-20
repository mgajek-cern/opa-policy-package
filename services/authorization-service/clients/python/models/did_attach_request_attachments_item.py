from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast

if TYPE_CHECKING:
  from ..models.did import Did





T = TypeVar("T", bound="DidAttachRequestAttachmentsItem")



@_attrs_define
class DidAttachRequestAttachmentsItem:
    """
        Attributes:
            parent (Did):
            children (list[Did]):
     """

    parent: Did
    children: list[Did]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.did import Did # noqa: PLC0415
        parent = self.parent.to_dict()

        children = []
        for children_item_data in self.children:
            children_item = children_item_data.to_dict()
            children.append(children_item)




        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "parent": parent,
            "children": children,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.did import Did # noqa: PLC0415
        d = dict(src_dict)
        parent = Did.from_dict(d.pop("parent"))




        children = []
        _children = d.pop("children")
        for children_item_data in (_children):
            children_item = Did.from_dict(children_item_data)



            children.append(children_item)


        did_attach_request_attachments_item = cls(
            parent=parent,
            children=children,
        )


        did_attach_request_attachments_item.additional_properties = d
        return did_attach_request_attachments_item

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

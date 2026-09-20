from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast

if TYPE_CHECKING:
  from ..models.context import Context
  from ..models.did import Did
  from ..models.subject import Subject





T = TypeVar("T", bound="DidDetachRequest")



@_attrs_define
class DidDetachRequest:
    """
        Attributes:
            subject (Subject): The principal the decision is about. type/id name the subject for
                logging, and are the only source of identity for credentials that
                carry no bearer token at all (e.g. the root bootstrap). Where a
                token is present, the claims the policy actually reads
                (entitlements, acr) come from that validated token, not from this
                object — there is no claims payload here to assert.
            parent (Did):
            children (list[Did]):
            context (Context):
     """

    subject: Subject
    parent: Did
    children: list[Did]
    context: Context
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.context import Context # noqa: PLC0415
        from ..models.did import Did # noqa: PLC0415
        from ..models.subject import Subject # noqa: PLC0415
        subject = self.subject.to_dict()

        parent = self.parent.to_dict()

        children = []
        for children_item_data in self.children:
            children_item = children_item_data.to_dict()
            children.append(children_item)



        context = self.context.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "subject": subject,
            "parent": parent,
            "children": children,
            "context": context,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.context import Context # noqa: PLC0415
        from ..models.did import Did # noqa: PLC0415
        from ..models.subject import Subject # noqa: PLC0415
        d = dict(src_dict)
        subject = Subject.from_dict(d.pop("subject"))




        parent = Did.from_dict(d.pop("parent"))




        children = []
        _children = d.pop("children")
        for children_item_data in (_children):
            children_item = Did.from_dict(children_item_data)



            children.append(children_item)


        context = Context.from_dict(d.pop("context"))




        did_detach_request = cls(
            subject=subject,
            parent=parent,
            children=children,
            context=context,
        )


        did_detach_request.additional_properties = d
        return did_detach_request

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

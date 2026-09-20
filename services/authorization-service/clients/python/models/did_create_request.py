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





T = TypeVar("T", bound="DidCreateRequest")



@_attrs_define
class DidCreateRequest:
    """
        Attributes:
            subject (Subject): The principal the decision is about. type/id name the subject for
                logging, and are the only source of identity for credentials that
                carry no bearer token at all (e.g. the root bootstrap). Where a
                token is present, the claims the policy actually reads
                (entitlements, acr) come from that validated token, not from this
                object — there is no claims payload here to assert.
            dids (list[Did]):
            context (Context):
     """

    subject: Subject
    dids: list[Did]
    context: Context
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.context import Context # noqa: PLC0415
        from ..models.did import Did # noqa: PLC0415
        from ..models.subject import Subject # noqa: PLC0415
        subject = self.subject.to_dict()

        dids = []
        for dids_item_data in self.dids:
            dids_item = dids_item_data.to_dict()
            dids.append(dids_item)



        context = self.context.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "subject": subject,
            "dids": dids,
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




        dids = []
        _dids = d.pop("dids")
        for dids_item_data in (_dids):
            dids_item = Did.from_dict(dids_item_data)



            dids.append(dids_item)


        context = Context.from_dict(d.pop("context"))




        did_create_request = cls(
            subject=subject,
            dids=dids,
            context=context,
        )


        did_create_request.additional_properties = d
        return did_create_request

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

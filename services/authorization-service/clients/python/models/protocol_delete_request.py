from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast

if TYPE_CHECKING:
  from ..models.context import Context
  from ..models.protocol import Protocol
  from ..models.rse import Rse
  from ..models.subject import Subject





T = TypeVar("T", bound="ProtocolDeleteRequest")



@_attrs_define
class ProtocolDeleteRequest:
    """
        Attributes:
            subject (Subject): The principal the decision is about. type/id name the subject for
                logging, and are the only source of identity for credentials that
                carry no bearer token at all (e.g. the root bootstrap). Where a
                token is present, the claims the policy actually reads
                (entitlements, acr) come from that validated token, not from this
                object — there is no claims payload here to assert.
            rse (Rse):
            protocol (Protocol):
            context (Context):
     """

    subject: Subject
    rse: Rse
    protocol: Protocol
    context: Context
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.context import Context # noqa: PLC0415
        from ..models.protocol import Protocol # noqa: PLC0415
        from ..models.rse import Rse # noqa: PLC0415
        from ..models.subject import Subject # noqa: PLC0415
        subject = self.subject.to_dict()

        rse = self.rse.to_dict()

        protocol = self.protocol.to_dict()

        context = self.context.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "subject": subject,
            "rse": rse,
            "protocol": protocol,
            "context": context,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.context import Context # noqa: PLC0415
        from ..models.protocol import Protocol # noqa: PLC0415
        from ..models.rse import Rse # noqa: PLC0415
        from ..models.subject import Subject # noqa: PLC0415
        d = dict(src_dict)
        subject = Subject.from_dict(d.pop("subject"))




        rse = Rse.from_dict(d.pop("rse"))




        protocol = Protocol.from_dict(d.pop("protocol"))




        context = Context.from_dict(d.pop("context"))




        protocol_delete_request = cls(
            subject=subject,
            rse=rse,
            protocol=protocol,
            context=context,
        )


        protocol_delete_request.additional_properties = d
        return protocol_delete_request

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

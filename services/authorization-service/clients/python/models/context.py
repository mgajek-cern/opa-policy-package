from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast
import datetime






T = TypeVar("T", bound="Context")



@_attrs_define
class Context:
    """
        Attributes:
            vo (str):
            request_time (datetime.datetime | Unset):
     """

    vo: str
    request_time: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        vo = self.vo

        request_time: str | Unset = UNSET
        if not isinstance(self.request_time, Unset):
            request_time = self.request_time.isoformat()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "vo": vo,
        })
        if request_time is not UNSET:
            field_dict["request_time"] = request_time

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vo = d.pop("vo")

        _request_time = d.pop("request_time", UNSET)
        request_time: datetime.datetime | Unset
        if isinstance(_request_time,  Unset):
            request_time = UNSET
        else:
            request_time = datetime.datetime.fromisoformat(_request_time)




        context = cls(
            vo=vo,
            request_time=request_time,
        )


        context.additional_properties = d
        return context

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

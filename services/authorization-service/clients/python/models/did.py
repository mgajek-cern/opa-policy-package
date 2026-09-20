from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.did_type import DidType
from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.scope import Scope





T = TypeVar("T", bound="Did")



@_attrs_define
class Did:
    """
        Attributes:
            scope (Scope):
            name (str):
            type_ (DidType | Unset):
     """

    scope: Scope
    name: str
    type_: DidType | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.scope import Scope # noqa: PLC0415
        scope = self.scope.to_dict()

        name = self.name

        type_: str | Unset = UNSET
        if not isinstance(self.type_, Unset):
            type_ = self.type_.value



        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "scope": scope,
            "name": name,
        })
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.scope import Scope # noqa: PLC0415
        d = dict(src_dict)
        scope = Scope.from_dict(d.pop("scope"))




        name = d.pop("name")

        _type_ = d.pop("type", UNSET)
        type_: DidType | Unset
        if isinstance(_type_,  Unset):
            type_ = UNSET
        else:
            type_ = DidType(_type_)




        did = cls(
            scope=scope,
            name=name,
            type_=type_,
        )


        did.additional_properties = d
        return did

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

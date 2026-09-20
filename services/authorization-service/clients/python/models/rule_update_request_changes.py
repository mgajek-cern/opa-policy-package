from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast






T = TypeVar("T", bound="RuleUpdateRequestChanges")



@_attrs_define
class RuleUpdateRequestChanges:
    """ Requested changes. `owner` present with any non-null value is a
    reassignment, including reassignment to the current owner.

        Attributes:
            owner (str | Unset):
            lifetime (int | None | Unset):
            rse_expression (str | Unset):
     """

    owner: str | Unset = UNSET
    lifetime: int | None | Unset = UNSET
    rse_expression: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        owner = self.owner

        lifetime: int | None | Unset
        if isinstance(self.lifetime, Unset):
            lifetime = UNSET
        else:
            lifetime = self.lifetime

        rse_expression = self.rse_expression


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if owner is not UNSET:
            field_dict["owner"] = owner
        if lifetime is not UNSET:
            field_dict["lifetime"] = lifetime
        if rse_expression is not UNSET:
            field_dict["rse_expression"] = rse_expression

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        owner = d.pop("owner", UNSET)

        def _parse_lifetime(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        lifetime = _parse_lifetime(d.pop("lifetime", UNSET))


        rse_expression = d.pop("rse_expression", UNSET)

        rule_update_request_changes = cls(
            owner=owner,
            lifetime=lifetime,
            rse_expression=rse_expression,
        )


        rule_update_request_changes.additional_properties = d
        return rule_update_request_changes

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

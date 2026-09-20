from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.did import Did





T = TypeVar("T", bound="RuleCreateRequestRule")



@_attrs_define
class RuleCreateRequestRule:
    """
        Attributes:
            owner (str): Account the new rule will belong to.
            locked (bool):
            dids (list[Did]):
            rse_expression (str | Unset):
            source_rse_expression (str | Unset):
     """

    owner: str
    locked: bool
    dids: list[Did]
    rse_expression: str | Unset = UNSET
    source_rse_expression: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.did import Did # noqa: PLC0415
        owner = self.owner

        locked = self.locked

        dids = []
        for dids_item_data in self.dids:
            dids_item = dids_item_data.to_dict()
            dids.append(dids_item)



        rse_expression = self.rse_expression

        source_rse_expression = self.source_rse_expression


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "owner": owner,
            "locked": locked,
            "dids": dids,
        })
        if rse_expression is not UNSET:
            field_dict["rse_expression"] = rse_expression
        if source_rse_expression is not UNSET:
            field_dict["source_rse_expression"] = source_rse_expression

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.did import Did # noqa: PLC0415
        d = dict(src_dict)
        owner = d.pop("owner")

        locked = d.pop("locked")

        dids = []
        _dids = d.pop("dids")
        for dids_item_data in (_dids):
            dids_item = Did.from_dict(dids_item_data)



            dids.append(dids_item)


        rse_expression = d.pop("rse_expression", UNSET)

        source_rse_expression = d.pop("source_rse_expression", UNSET)

        rule_create_request_rule = cls(
            owner=owner,
            locked=locked,
            dids=dids,
            rse_expression=rse_expression,
            source_rse_expression=source_rse_expression,
        )


        rule_create_request_rule.additional_properties = d
        return rule_create_request_rule

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

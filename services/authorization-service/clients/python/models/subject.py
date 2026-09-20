from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.subject_type import SubjectType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.subject_properties import SubjectProperties


T = TypeVar("T", bound="Subject")


@_attrs_define
class Subject:
    """The principal the decision is about. Its claims are asserted by the
    authenticated PEP; the service does not re-validate the token (design-005).

        Attributes:
            type_ (SubjectType):
            id (str): Account name for rucio_account; "<sub>@<iss>" for oidc_subject.
            properties (SubjectProperties | Unset):
    """

    type_: SubjectType
    id: str
    properties: SubjectProperties | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        id = self.id

        properties: dict[str, Any] | Unset = UNSET
        if not isinstance(self.properties, Unset):
            properties = self.properties.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "id": id,
            }
        )
        if properties is not UNSET:
            field_dict["properties"] = properties

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.subject_properties import SubjectProperties  # noqa: PLC0415

        d = dict(src_dict)
        type_ = SubjectType(d.pop("type"))

        id = d.pop("id")

        _properties = d.pop("properties", UNSET)
        properties: SubjectProperties | Unset
        if isinstance(_properties, Unset):
            properties = UNSET
        else:
            properties = SubjectProperties.from_dict(_properties)

        subject = cls(
            type_=type_,
            id=id,
            properties=properties,
        )

        subject.additional_properties = d
        return subject

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

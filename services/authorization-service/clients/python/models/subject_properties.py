from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.token import Token


T = TypeVar("T", bound="SubjectProperties")


@_attrs_define
class SubjectProperties:
    """
    Attributes:
        token (Token | Unset): The token presented by the subject: identifiers for audit, plus the
            claims the policy reads. Absent for non-token credentials, such as the
            root bootstrap.
    """

    token: Token | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        token: dict[str, Any] | Unset = UNSET
        if not isinstance(self.token, Unset):
            token = self.token.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if token is not UNSET:
            field_dict["token"] = token

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.token import Token  # noqa: PLC0415

        d = dict(src_dict)
        _token = d.pop("token", UNSET)
        token: Token | Unset
        if isinstance(_token, Unset):
            token = UNSET
        else:
            token = Token.from_dict(_token)

        subject_properties = cls(
            token=token,
        )

        subject_properties.additional_properties = d
        return subject_properties

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

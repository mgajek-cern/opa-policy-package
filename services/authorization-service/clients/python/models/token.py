from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Token")


@_attrs_define
class Token:
    """The token presented by the subject: identifiers for audit, plus the
    claims the policy reads. Absent for non-token credentials, such as the
    root bootstrap.

        Attributes:
            iss (str):
            sub (str):
            jti (str | Unset):
            aud (list[str] | Unset):
            entitlements (list[str] | Unset):
            acr (str | Unset):
    """

    iss: str
    sub: str
    jti: str | Unset = UNSET
    aud: list[str] | Unset = UNSET
    entitlements: list[str] | Unset = UNSET
    acr: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        iss = self.iss

        sub = self.sub

        jti = self.jti

        aud: list[str] | Unset = UNSET
        if not isinstance(self.aud, Unset):
            aud = self.aud

        entitlements: list[str] | Unset = UNSET
        if not isinstance(self.entitlements, Unset):
            entitlements = self.entitlements

        acr = self.acr

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "iss": iss,
                "sub": sub,
            }
        )
        if jti is not UNSET:
            field_dict["jti"] = jti
        if aud is not UNSET:
            field_dict["aud"] = aud
        if entitlements is not UNSET:
            field_dict["entitlements"] = entitlements
        if acr is not UNSET:
            field_dict["acr"] = acr

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        iss = d.pop("iss")

        sub = d.pop("sub")

        jti = d.pop("jti", UNSET)

        aud = cast(list[str], d.pop("aud", UNSET))

        entitlements = cast(list[str], d.pop("entitlements", UNSET))

        acr = d.pop("acr", UNSET)

        token = cls(
            iss=iss,
            sub=sub,
            jti=jti,
            aud=aud,
            entitlements=entitlements,
            acr=acr,
        )

        token.additional_properties = d
        return token

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

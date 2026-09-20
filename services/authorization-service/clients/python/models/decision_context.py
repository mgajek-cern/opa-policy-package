from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decision_context_policy import DecisionContextPolicy


T = TypeVar("T", bound="DecisionContext")


@_attrs_define
class DecisionContext:
    """
    Attributes:
        decision_id (str | Unset): Identifier of the audit record for this decision. PEPs log it
            next to their own request id to correlate the two.
        reason_admin (str | Unset): Operator-facing reason. Not for end users.
        policy (DecisionContextPolicy | Unset): The policy version that produced the decision.
    """

    decision_id: str | Unset = UNSET
    reason_admin: str | Unset = UNSET
    policy: DecisionContextPolicy | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        decision_id = self.decision_id

        reason_admin = self.reason_admin

        policy: dict[str, Any] | Unset = UNSET
        if not isinstance(self.policy, Unset):
            policy = self.policy.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if decision_id is not UNSET:
            field_dict["decision_id"] = decision_id
        if reason_admin is not UNSET:
            field_dict["reason_admin"] = reason_admin
        if policy is not UNSET:
            field_dict["policy"] = policy

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decision_context_policy import DecisionContextPolicy  # noqa: PLC0415

        d = dict(src_dict)
        decision_id = d.pop("decision_id", UNSET)

        reason_admin = d.pop("reason_admin", UNSET)

        _policy = d.pop("policy", UNSET)
        policy: DecisionContextPolicy | Unset
        if isinstance(_policy, Unset):
            policy = UNSET
        else:
            policy = DecisionContextPolicy.from_dict(_policy)

        decision_context = cls(
            decision_id=decision_id,
            reason_admin=reason_admin,
            policy=policy,
        )

        decision_context.additional_properties = d
        return decision_context

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

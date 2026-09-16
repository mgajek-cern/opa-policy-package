package vo.authz.v3

import rego.v1

# Top-level entry point

default allow := false

allow if { _action_allowed }

# Action sets — Phase 3 sets plus _replica_actions (see below)

_rse_actions      := {"add_rse", "update_rse", "del_rse",
                       "add_rse_attribute", "del_rse_attribute"}
_rule_actions     := {"add_rule", "del_rule", "update_rule"}
_did_actions      := {"add_did", "add_dids", "attach_dids", "detach_dids",
                       "attach_dids_to_dids"}
_protocol_actions := {"add_protocol", "del_protocol", "update_protocol"}

# Replica actions were previously unlisted, so they fell through to
# privileged-only via the _is_known_action catch-all. Rucio's replica
# registration path (add_replicas) is needed by any account that seeds
# files, so it gets its own rule; state changes and deletions stay
# privileged.
#
# NOT included here: skip_availability_check. Rucio treats it as an
# admin-only escalation and so do we — an account that needs it should
# hold an admin group rather than have the policy relaxed. The Rucio
# client only requests it when ignore_availability=True is passed to
# add_replicas.
_replica_actions  := {"add_replicas", "update_replicas_states", "delete_replicas"}

_all_known_actions := _rule_actions | _rse_actions | _did_actions |
                      _protocol_actions | _replica_actions

# Dispatch

_action_allowed if { input.action == "add_rule";                                      _perm_add_rule }
_action_allowed if { input.action == "del_rule";                                      _perm_rule_owner }
_action_allowed if { input.action == "update_rule";                                   _perm_rule_owner_and_data }
_action_allowed if { input.action == "add_rse";                                       _perm_add_rse }
_action_allowed if { input.action == "update_rse";                                    _perm_update_rse }
_action_allowed if { input.action in (_rse_actions - {"add_rse","update_rse"});       _is_privileged }
_action_allowed if { input.action in _did_actions;                                    _perm_did_action }
_action_allowed if { input.action in _protocol_actions;                               _perm_protocol_action }
_action_allowed if { input.action == "add_replicas";                                  _perm_add_replicas }
_action_allowed if { input.action in (_replica_actions - {"add_replicas"});           _is_privileged }

_action_allowed if {
    not _is_known_action(input.action)
    _is_privileged
}

_is_known_action(action) if { action in _all_known_actions }

# add_rule

_perm_add_rule if {
    _dst_rse_name_valid
    _src_rse_name_valid
    input.kwargs.account == input.issuer
    input.kwargs.locked == false
    count(input.kwargs.dids) > 0
    every did in input.kwargs.dids { did.scope in input.kwargs.owned_scopes }
}

_perm_add_rule if {
    _dst_rse_name_valid
    _src_rse_name_valid
    _is_privileged
}

# del_rule / update_rule — owner self-service

_rule_reassignment_requested if {
    object.get(input.kwargs, ["options", "account"], null) != null
}

_perm_rule_owner if { _is_privileged }
_perm_rule_owner if { input.kwargs.rule_owner == input.issuer }

_perm_rule_owner_and_data if { _is_privileged }
_perm_rule_owner_and_data if {
    not _rule_reassignment_requested
    input.kwargs.rule_owner == input.issuer
    input.kwargs.rule_scope in input.kwargs.owned_scopes
}

# add_rse / update_rse

_perm_add_rse if { _is_privileged; _rse_name_valid(input.kwargs.rse) }

_perm_update_rse if { _is_privileged; not input.kwargs.parameters.rse }
_perm_update_rse if {
    _is_privileged
    _rse_name_valid(input.kwargs.parameters.rse)
}

# add_replicas
#
# kwargs carry only {rse, rse_id} — no scope — so there is no ownership
# signal to gate on. Two non-privileged paths:
#
#   - a group mapped to "user" in the bundle, on an RSE whose name passes
#     the convention. This is the only rule that distinguishes a mapped
#     non-admin group from an account with no groups at all.
#   - data.vo.policy.allow_replica_writes_to_allowlisted_rses, which drops
#     the group requirement entirely. Broader; default is off.

_perm_add_replicas if { _is_privileged }

_perm_add_replicas if {
    _has_privilege_level("user")
    _rse_name_valid(input.kwargs.rse)
}

_perm_add_replicas if {
    data.vo.policy.allow_replica_writes_to_allowlisted_rses == true
    _rse_name_valid(input.kwargs.rse)
}

# DID actions

_perm_did_action if { _is_privileged }

_perm_did_action if { input.kwargs.scope in input.kwargs.owned_scopes }

_perm_did_action if {
    input.action == "attach_dids_to_dids"
    attachment := input.kwargs.attachments[_]
    attachment.scope in input.kwargs.owned_scopes
}

_perm_did_action if {
    input.action == "add_dids"
    count(input.kwargs.dids) > 0
    every did in input.kwargs.dids { did.scope in input.kwargs.owned_scopes }
}

# Protocol actions

_default_allowed_schemes := {"davs", "s3", "https", "root", "xrdhttp", "gsiftp"}

_allowed_schemes := data.vo.policy.allowed_schemes if {
    data.vo.policy.allowed_schemes
} else := _default_allowed_schemes

# del_protocol and some update_protocol calls carry no scheme; without this
# clause they denied even for privileged accounts.
_perm_protocol_action if {
    _is_privileged
    not input.kwargs.scheme
}

_perm_protocol_action if {
    _is_privileged
    lower(input.kwargs.scheme) in _allowed_schemes
}

# RSE naming — data-driven with hardcoded fallback

_default_known_rse_types := {
    "DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK",
}

_known_rse_types := data.vo.policy.known_rse_types if {
    data.vo.policy.known_rse_types
} else := _default_known_rse_types

_rse_name_valid(name) if {
    regex.match(`^[A-Z0-9]+_[A-Z0-9]+$`, name)
    parts := split(name, "_")
    count(parts) == 2
    parts[1] in _known_rse_types
}

_dst_rse_name_valid if { not input.kwargs.rse_expression }
_dst_rse_name_valid if { _is_expression(input.kwargs.rse_expression) }
_dst_rse_name_valid if {
    not _is_expression(input.kwargs.rse_expression)
    _rse_name_valid(input.kwargs.rse_expression)
}

_src_rse_name_valid if { not input.kwargs.source_rse_expression }
_src_rse_name_valid if { _is_expression(input.kwargs.source_rse_expression) }
_src_rse_name_valid if {
    not _is_expression(input.kwargs.source_rse_expression)
    _rse_name_valid(input.kwargs.source_rse_expression)
}

_is_expression(expr) if { contains(expr, "=") }
_is_expression(expr) if { contains(expr, "&") }
_is_expression(expr) if { contains(expr, "|") }

# Authentication context
#
# data.vo.policy.required_acr, when set, is compared against the token's acr
# claim before any group can grant privilege. Absent by default, so the
# testbed behaves as before; set it at runtime to require e.g.
# "https://refeds.org/profile/mfa" for privileged actions.
#
# This gates the OIDC privilege path only. The root bootstrap below has no
# token and therefore no acr — requiring one there would leave no way to
# bring a stack up.

_acr_satisfied if { not data.vo.policy.required_acr }

_acr_satisfied if { input.token.acr == data.vo.policy.required_acr }

# Privilege — derived from wlcg.groups, not is_root/is_admin flags
#
# data.vo.group_policy maps WLCG group paths to privilege levels, e.g.:
#   { "/rucio/admins": "admin", "/atlas/production": "admin",
#     "/rucio/users": "user", ... }
#
# Falls back to hardcoded defaults when no bundle is loaded (CI / unit tests).

default _is_privileged := false

# Bootstrap: root account has no OIDC token — allow unconditionally.
_is_privileged if { input.issuer == "root" }

# OIDC path: any group mapping to "admin", subject to the acr constraint.
_is_privileged if {
    _acr_satisfied
    _has_privilege_level("admin")
}

# True when any group in the token maps to the given level. "admin" grants
# privilege; "user" is consulted by _perm_add_replicas, so a mapped group is
# no longer equivalent to no group at all.
_has_privilege_level(level) if {
    group := input.token.groups[_]
    _group_privilege(group) == level
}

# Bundle-driven group policy. When a bundle IS loaded this is the only
# source of privilege — the fallbacks below do not apply, so the bundle
# must contain /rucio/admins or admin tokens will be denied.
_group_privilege(group) := level if {
    level := data.vo.group_policy[group]
}

# Hardcoded fallbacks — used when no bundle is loaded (CI / testing).
_group_privilege(group) := "admin" if {
    not data.vo.group_policy
    group in {"/rucio/admins", "/atlas/production"}
}

_group_privilege(group) := "user" if {
    not data.vo.group_policy
    group in {"/rucio/users", "/atlas/users"}
}

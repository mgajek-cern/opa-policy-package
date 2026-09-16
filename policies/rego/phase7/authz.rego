package vo.authz.v6

import rego.v1

# Phase 7: the phase 6 policy, restructured to match the Authorization
# Service contract (services/authorization-service/api/openapi.yaml,
# design-005).
#
# Every action with a typed endpoint in the contract has exactly one dispatch
# line and one named rule here. Every other action reaches the catch-all,
# which is what the contract's privileged-operations endpoint maps onto.
# tests/test_phase7_opa.py checks that the two lists agree.
#
# Input shape is unchanged from phase 6 (issuer, action, token, kwargs), so
# the v0 service adapter and the phase 6 permission.py can both drive it.
#
# Decisions are identical to phase 6 except where marked "Changed from
# phase 6" below.
#
# Privilege model by contract tag:
#   rules, dids   ownership (design-003, design-004), or privilege
#   rses          privilege only: RSEs have no owning account in Rucio
#   protocols     privilege only: protocols belong to RSEs
#   replicas      ownership of every file's scope, or privilege

# Top-level entry point

default allow := false

allow if { _action_allowed }

# Action sets: one per contract tag
#
# These sets are the contract's typed endpoints. Adding an action here without
# a dispatch line denies it for everyone, root included, because it is no
# longer caught by the catch-all. The alignment test catches that.
#
# Deliberately NOT listed, so they reach the catch-all (privileged only):
#   update_replicas_states  the contract routes it to privileged-operations
#   skip_availability_check an admin-only escalation, as in phase 6
#   approve_rule, reduce_rule, move_rule, access_rule_vo  (design-004)

_rule_actions     := {"add_rule", "update_rule", "del_rule"}
_did_actions      := {"add_did", "add_dids", "attach_dids", "attach_dids_to_dids",
                       "detach_dids"}
_rse_actions      := {"add_rse", "update_rse", "del_rse",
                       "add_rse_attribute", "del_rse_attribute"}
_protocol_actions := {"add_protocol", "update_protocol", "del_protocol"}
_replica_actions  := {"add_replicas", "delete_replicas"}

_all_known_actions := _rule_actions | _did_actions | _rse_actions |
                      _protocol_actions | _replica_actions

# Dispatch: one line per typed endpoint action

# rules
_action_allowed if { input.action == "add_rule";            _perm_add_rule }
_action_allowed if { input.action == "update_rule";         _perm_update_rule }
_action_allowed if { input.action == "del_rule";            _perm_del_rule }

# dids
_action_allowed if { input.action == "add_did";             _perm_add_did }
_action_allowed if { input.action == "add_dids";            _perm_add_dids }
_action_allowed if { input.action == "attach_dids";         _perm_attach_dids }
_action_allowed if { input.action == "attach_dids_to_dids"; _perm_attach_dids_to_dids }
_action_allowed if { input.action == "detach_dids";         _perm_detach_dids }

# rses
_action_allowed if { input.action == "add_rse";             _perm_add_rse }
_action_allowed if { input.action == "update_rse";          _perm_update_rse }
_action_allowed if { input.action == "del_rse";             _perm_del_rse }
_action_allowed if { input.action == "add_rse_attribute";   _perm_add_rse_attribute }
_action_allowed if { input.action == "del_rse_attribute";   _perm_del_rse_attribute }

# protocols
_action_allowed if { input.action == "add_protocol";        _perm_add_protocol }
_action_allowed if { input.action == "update_protocol";     _perm_update_protocol }
_action_allowed if { input.action == "del_protocol";        _perm_del_protocol }

# replicas
_action_allowed if { input.action == "add_replicas";        _perm_add_replicas }
_action_allowed if { input.action == "delete_replicas";     _perm_delete_replicas }

# privileged-operations: everything else
_action_allowed if {
    not _is_known_action(input.action)
    _is_privileged
}

_is_known_action(action) if { action in _all_known_actions }

# Rules

# add_rule: rule ownership and data ownership (design-004)

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

# update_rule: rule owner and target scope owner, no reassignment (design-004)

_rule_reassignment_requested if {
    object.get(input.kwargs, ["options", "account"], null) != null
}

_perm_update_rule if { _is_privileged }
_perm_update_rule if {
    not _rule_reassignment_requested
    input.kwargs.rule_owner == input.issuer
    input.kwargs.rule_scope in input.kwargs.owned_scopes
}

# del_rule: rule owner alone (design-004)

_perm_del_rule if { _is_privileged }
_perm_del_rule if { input.kwargs.rule_owner == input.issuer }

# DIDs (design-003)
#
# Changed from phase 6: phase 6 had one _perm_did_action shared by all five
# actions, so its `kwargs.scope in owned_scopes` clause also applied to
# add_dids and attach_dids_to_dids, whose requests carry lists rather than a
# top-level scope. Here each action checks only the fields its request has.

_perm_add_did if { _is_privileged }
_perm_add_did if { input.kwargs.scope in input.kwargs.owned_scopes }

_perm_add_dids if { _is_privileged }
_perm_add_dids if {
    count(input.kwargs.dids) > 0
    every did in input.kwargs.dids { did.scope in input.kwargs.owned_scopes }
}

_perm_attach_dids if { _is_privileged }
_perm_attach_dids if { input.kwargs.scope in input.kwargs.owned_scopes }

# Changed from phase 6: every attachment's scope must be owned, not just one.
# The contract permits a multi-resource request only if every resource is
# permitted, and add_dids already required every scope.
_perm_attach_dids_to_dids if { _is_privileged }
_perm_attach_dids_to_dids if {
    count(input.kwargs.attachments) > 0
    every attachment in input.kwargs.attachments {
        attachment.scope in input.kwargs.owned_scopes
    }
}

_perm_detach_dids if { _is_privileged }
_perm_detach_dids if { input.kwargs.scope in input.kwargs.owned_scopes }

# RSEs

_perm_add_rse if {
    _is_privileged
    _rse_name_valid(input.kwargs.rse)
}

_perm_update_rse if {
    _is_privileged
    not input.kwargs.parameters.rse
}

_perm_update_rse if {
    _is_privileged
    _rse_name_valid(input.kwargs.parameters.rse)
}

# del_rse, add_rse_attribute, del_rse_attribute
#
# Privileged only, as in phase 6. The rses table has no account column, so
# there is no owner to gate on: RSEs are infrastructure, not data. RSE
# attributes such as fts or lfn2pfn_algorithm change how data moves, which
# is why these stay with administrators.

_perm_del_rse if { _is_privileged }

_perm_add_rse_attribute if { _is_privileged }

_perm_del_rse_attribute if { _is_privileged }

# Protocols

_default_allowed_schemes := {"davs", "s3", "https", "root", "xrdhttp", "gsiftp"}

_allowed_schemes := data.vo.policy.allowed_schemes if {
    data.vo.policy.allowed_schemes
} else := _default_allowed_schemes

# del_protocol and some update_protocol calls carry no scheme.
_protocol_scheme_allowed if { not input.kwargs.scheme }
_protocol_scheme_allowed if { lower(input.kwargs.scheme) in _allowed_schemes }

_perm_add_protocol if {
    _is_privileged
    _protocol_scheme_allowed
}

_perm_update_protocol if {
    _is_privileged
    _protocol_scheme_allowed
}

_perm_del_protocol if {
    _is_privileged
    _protocol_scheme_allowed
}

# Replicas
#
# Changed from phase 6: replica actions are gated on data ownership.
#
# A replica has no account column; its ownership is its DID's, and this
# policy resolves DID ownership at the scope grain (design-003). A
# non-privileged subject may register or delete replicas only when it owns
# the scope of every file in the request.
#
# PREREQUISITE: the Rucio gateway passes only {rse, rse_id} to
# has_permission for add_replicas and delete_replicas. Until it also passes
# `files`, and permission.py forwards them and resolves their scopes into
# owned_scopes, every non-privileged replica request is denied here. Root
# and admin paths are unaffected. See design-005, "Replica ownership".

_all_file_scopes_owned if {
    count(input.kwargs.files) > 0
    every file in input.kwargs.files { file.scope in input.kwargs.owned_scopes }
}

# add_replicas
#
# Non-privileged paths, both requiring ownership of every file's scope and an
# RSE name that passes _rse_name_valid (which includes the testbed allowlist):
#
#   - an entitlement mapped to "user";
#   - data.vo.policy.allow_replica_writes_to_allowlisted_rses, which drops
#     the entitlement requirement but not ownership. Off by default.

_perm_add_replicas if { _is_privileged }

_perm_add_replicas if {
    _has_privilege_level("user")
    _rse_name_valid(input.kwargs.rse)
    _all_file_scopes_owned
}

_perm_add_replicas if {
    data.vo.policy.allow_replica_writes_to_allowlisted_rses == true
    _rse_name_valid(input.kwargs.rse)
    _all_file_scopes_owned
}

# delete_replicas
#
# A "user" entitlement and ownership of every file's scope, as for
# registration. There is no RSE-name check: removing a replica record needs
# no naming guard. The reaper calls core directly and never reaches
# has_permission, so it is unaffected.

_perm_delete_replicas if { _is_privileged }

_perm_delete_replicas if {
    _has_privilege_level("user")
    _all_file_scopes_owned
}

# RSE naming: data-driven with hardcoded fallback

_default_known_rse_types := {
    "DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK",
}

_known_rse_types := data.vo.policy.known_rse_types if {
    data.vo.policy.known_rse_types
} else := _default_known_rse_types

_rse_name_valid(name) if {
    name in _allowlisted_rse_names
}

_rse_name_valid(name) if {
    not name in _allowlisted_rse_names
    regex.match(`^[A-Z0-9]+_[A-Z0-9]+$`, name)
    parts := split(name, "_")
    count(parts) == 2
    parts[1] in _known_rse_types
}

_default_allowlisted_rse_names := set()

_allowlisted_rse_names := data.vo.policy.allowlisted_rse_names if {
    data.vo.policy.allowlisted_rse_names
} else := _default_allowlisted_rse_names

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
# data.vo.policy.required_acr, when set, must match the token's acr claim
# before any entitlement grants privilege. It gates the OIDC privilege path
# only: root has no token and therefore no acr.

_acr_satisfied if { not data.vo.policy.required_acr }

_acr_satisfied if { input.token.acr == data.vo.policy.required_acr }

# Privilege: derived from the entitlements claim

default _is_privileged := false

# Bootstrap: the root account has no OIDC token; allow unconditionally.
_is_privileged if { input.issuer == "root" }

# OIDC path: any entitlement mapping to "admin", subject to acr.
_is_privileged if {
    _acr_satisfied
    _has_privilege_level("admin")
}

_has_privilege_level(level) if {
    entitlement := input.token.entitlements[_]
    _entitlement_privilege(entitlement) == level
}

# Bundle-driven entitlement policy. When a bundle is loaded it is the only
# source of privilege, and the fallbacks below do not apply.
_entitlement_privilege(entitlement) := level if {
    level := data.vo.entitlement_policy[entitlement]
}

# Hardcoded fallbacks, used when no bundle is loaded (CI and unit tests).
_entitlement_privilege(entitlement) := "admin" if {
    not data.vo.entitlement_policy
    entitlement in {
        "urn:example:aai.example.org:group:rucio-admins:role=member",
        "urn:example:aai.example.org:group:atlas-production:role=member",
    }
}

_entitlement_privilege(entitlement) := "user" if {
    not data.vo.entitlement_policy
    entitlement in {
        "urn:example:aai.example.org:group:rucio-users:role=member",
        "urn:example:aai.example.org:group:atlas-users:role=member",
    }
}

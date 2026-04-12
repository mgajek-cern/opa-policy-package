package vo.authz.v3

import rego.v1

# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

default allow := false

allow if { _action_allowed }

# ---------------------------------------------------------------------------
# Action sets — identical to Phase 3
# ---------------------------------------------------------------------------

_rse_actions      := {"add_rse", "update_rse", "del_rse",
                       "add_rse_attribute", "del_rse_attribute"}
_rule_actions     := {"add_rule", "del_rule", "update_rule", "approve_rule"}
_did_actions      := {"add_did", "add_dids", "attach_dids", "detach_dids",
                       "attach_dids_to_dids"}
_protocol_actions := {"add_protocol", "del_protocol", "update_protocol"}

_all_known_actions := _rule_actions | _rse_actions | _did_actions | _protocol_actions

# ---------------------------------------------------------------------------
# Dispatch — identical to Phase 3
# ---------------------------------------------------------------------------

_action_allowed if { input.action == "add_rule";                                _perm_add_rule }
_action_allowed if { input.action in {"del_rule", "update_rule"};               _perm_rule_owner_or_privileged }
_action_allowed if { input.action == "approve_rule";                            _is_privileged }
_action_allowed if { input.action == "add_rse";                                 _perm_add_rse }
_action_allowed if { input.action == "update_rse";                              _perm_update_rse }
_action_allowed if { input.action in (_rse_actions - {"add_rse","update_rse"}); _is_privileged }
_action_allowed if { input.action in _did_actions;                              _perm_did_action }
_action_allowed if { input.action in _protocol_actions;                         _perm_protocol_action }

_action_allowed if {
    not _is_known_action(input.action)
    _is_privileged
}

_is_known_action(action) if { action in _all_known_actions }

# ---------------------------------------------------------------------------
# add_rule
# ---------------------------------------------------------------------------

_perm_add_rule if {
    _protocol_combo_allowed
    _dst_rse_name_valid
    _src_rse_name_valid
    input.kwargs.account == input.issuer
    input.kwargs.locked == false
}

_perm_add_rule if {
    _protocol_combo_allowed
    _dst_rse_name_valid
    _src_rse_name_valid
    _is_privileged
}

# ---------------------------------------------------------------------------
# del_rule / update_rule — owner self-service
# ---------------------------------------------------------------------------

_perm_rule_owner_or_privileged if { input.kwargs.account == input.issuer }
_perm_rule_owner_or_privileged if { _is_privileged }

# ---------------------------------------------------------------------------
# add_rse / update_rse
# ---------------------------------------------------------------------------

_perm_add_rse if { _is_privileged; _rse_name_valid(input.kwargs.rse) }

_perm_update_rse if { _is_privileged; not input.kwargs.parameters.rse }
_perm_update_rse if {
    _is_privileged
    _rse_name_valid(input.kwargs.parameters.rse)
}

# ---------------------------------------------------------------------------
# DID actions
# ---------------------------------------------------------------------------

_perm_did_action if { _is_privileged }
_perm_did_action if { input.kwargs.scope == "mock" }
_perm_did_action if { startswith(input.kwargs.scope, input.issuer) }
_perm_did_action if {
    input.action == "attach_dids_to_dids"
    attachment := input.kwargs.attachments[_]
    startswith(attachment.scope, input.issuer)
}

# ---------------------------------------------------------------------------
# Protocol actions
# ---------------------------------------------------------------------------

_default_allowed_schemes := {"davs", "s3", "https", "root", "xrdhttp", "gsiftp"}

_allowed_schemes := data.vo.policy.allowed_schemes if {
    data.vo.policy.allowed_schemes
} else := _default_allowed_schemes

_perm_protocol_action if {
    _is_privileged
    lower(input.kwargs.scheme) in _allowed_schemes
}

# ---------------------------------------------------------------------------
# Protocol combo rules — data-driven with hardcoded fallback
# ---------------------------------------------------------------------------

_default_allowed_combos := {
    ["webdav", "webdav"], ["s3", "webdav"], ["xrdhttp", "webdav"],
    ["s3", "xrdhttp"],    ["xrdhttp", "xrdhttp"],
}

_allowed_combos := data.vo.policy.allowed_protocol_combos if {
    data.vo.policy.allowed_protocol_combos
} else := _default_allowed_combos

_protocol_combo_allowed if {
    not input.kwargs.source_protocol
    not input.kwargs.dst_protocol
}
_protocol_combo_allowed if {
    src := lower(input.kwargs.source_protocol)
    dst := lower(input.kwargs.dst_protocol)
    [src, dst] in _allowed_combos
}

# ---------------------------------------------------------------------------
# RSE naming — data-driven with hardcoded fallback
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Privilege — Phase 4: derived from wlcg.groups, not is_root/is_admin flags
#
# data.vo.group_policy maps WLCG group paths to privilege levels, e.g.:
#   { "/rucio/admins": "admin", "/atlas/production": "admin", ... }
#
# Falls back to hardcoded defaults when no bundle is loaded (CI / unit tests).
# ---------------------------------------------------------------------------

default _is_privileged := false

# Bootstrap: root account has no OIDC token — allow unconditionally.
_is_privileged if { input.issuer == "root" }

# OIDC path: any group in token.groups that maps to "admin" grants privilege.
_is_privileged if {
    group := input.token.groups[_]
    _group_privilege(group) == "admin"
}

# Bundle-driven group policy.
_group_privilege(group) := level if {
    level := data.vo.group_policy[group]
}

# Hardcoded fallback — used when no bundle is loaded (CI / testing).
_group_privilege(group) := "admin" if {
    not data.vo.group_policy
    group in {"/rucio/admins", "/atlas/production"}
}

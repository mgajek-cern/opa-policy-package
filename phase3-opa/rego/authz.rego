package vo.authz.v2

import rego.v1

# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

default allow := false

allow if {
    _action_allowed
}

# ---------------------------------------------------------------------------
# Action sets
# ---------------------------------------------------------------------------

_rse_actions      := {"add_rse", "update_rse", "del_rse",
                       "add_rse_attribute", "del_rse_attribute"}
_rule_actions     := {"add_rule", "del_rule", "update_rule", "approve_rule"}
_did_actions      := {"add_did", "add_dids", "attach_dids", "detach_dids",
                       "attach_dids_to_dids"}
_protocol_actions := {"add_protocol", "del_protocol", "update_protocol"}

_all_known_actions := _rule_actions | _rse_actions | _did_actions | _protocol_actions

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_action_allowed if {
    input.action == "add_rule"
    _perm_add_rule
}

_action_allowed if {
    input.action in {"del_rule", "update_rule"}
    _perm_rule_owner_or_privileged
}

_action_allowed if {
    input.action == "approve_rule"
    _is_privileged
}

_action_allowed if {
    input.action == "add_rse"
    _perm_add_rse
}

_action_allowed if {
    input.action == "update_rse"
    _perm_update_rse
}

_action_allowed if {
    input.action in (_rse_actions - {"add_rse", "update_rse"})
    _is_privileged
}

_action_allowed if {
    input.action in _did_actions
    _perm_did_action
}

_action_allowed if {
    input.action in _protocol_actions
    _perm_protocol_action
}

# Privileged-only fallback for everything not in a known action set.
# FIX: `not x in set` in Rego v1 parses as `(not x) in set` — ambiguous
# precedence bug. Use a named helper to make negation unambiguous.
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
    # FIX: use == false rather than `not input.kwargs.locked`
    # `not` on a boolean value works, but == false is explicit and avoids
    # the case where locked is absent (undefined) being treated as unlocked.
    input.kwargs.locked == false
}

_perm_add_rule if {
    _protocol_combo_allowed
    _dst_rse_name_valid
    _src_rse_name_valid
    _is_privileged
}

# ---------------------------------------------------------------------------
# del_rule / update_rule — rule owner self-service (Phase 3 addition)
# ---------------------------------------------------------------------------

_perm_rule_owner_or_privileged if {
    input.kwargs.account == input.issuer
}

_perm_rule_owner_or_privileged if {
    _is_privileged
}

# ---------------------------------------------------------------------------
# add_rse / update_rse
# ---------------------------------------------------------------------------

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
    new_name := input.kwargs.parameters.rse
    _rse_name_valid(new_name)
}

# ---------------------------------------------------------------------------
# DID actions — scope-owner or privileged
# ---------------------------------------------------------------------------

_perm_did_action if { _is_privileged }

_perm_did_action if { input.kwargs.scope == "mock" }

_perm_did_action if {
    startswith(input.kwargs.scope, input.issuer)
}

_perm_did_action if {
    input.action == "attach_dids_to_dids"
    attachment := input.kwargs.attachments[_]
    startswith(attachment.scope, input.issuer)
}

# ---------------------------------------------------------------------------
# Protocol actions — privileged + scheme allowlist
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
    ["webdav", "webdav"],
    ["s3", "webdav"],
    ["xrdhttp", "webdav"],
    ["s3", "xrdhttp"],
    ["xrdhttp", "xrdhttp"],
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
# Shared helpers
# ---------------------------------------------------------------------------

# FIX: explicit default prevents partial evaluation from treating an
# undefined _is_privileged as falsy in unexpected ways.
default _is_privileged := false

_is_privileged if { input.is_root == true }

_is_privileged if { input.is_admin == true }

# FIX: require explicit `== true` — `data.vo.admins[input.issuer]` alone
# would fire if the value is any truthy object, not just boolean true.
_is_privileged if { data.vo.admins[input.issuer] == true }

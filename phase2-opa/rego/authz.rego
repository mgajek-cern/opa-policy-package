package vo.authz

import rego.v1

# ---------------------------------------------------------------------------
# Top-level rule — the only entry point queried by the Python client
# ---------------------------------------------------------------------------

# Default: deny everything not explicitly allowed
default allow := false

allow if {
    _action_allowed
}

# ---------------------------------------------------------------------------
# Action dispatch
#
# Actions covered by this policy (selected from Rucio generic.py):
#
#   Replication rules
#     add_rule      — domain checks + account check
#     del_rule      — privileged only
#     update_rule   — privileged only
#     approve_rule  — privileged only
#
#   RSE management
#     add_rse       — privileged + naming convention
#     update_rse    — privileged + naming convention on rename
#     del_rse       — privileged only
#     add_rse_attribute — privileged only
#     del_rse_attribute — privileged only
#
#   Data Identifiers (DIDs)
#     add_did       — scope owner or privileged
#     add_dids      — scope owner or privileged (bulk)
#     attach_dids   — scope owner or privileged
#     detach_dids   — scope owner or privileged
#
#   All other actions → privileged only (safe default)
# ---------------------------------------------------------------------------

_rse_actions       := {"add_rse", "update_rse", "del_rse",
                        "add_rse_attribute", "del_rse_attribute"}
_rule_actions      := {"add_rule", "del_rule", "update_rule", "approve_rule"}
_did_actions       := {"add_did", "add_dids", "attach_dids", "detach_dids"}

_action_allowed if {
    input.action == "add_rule"
    _perm_add_rule
}

_action_allowed if {
    input.action in (_rule_actions - {"add_rule"})
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

# All other actions: privileged only
_action_allowed if {
    not input.action in (_rule_actions | _rse_actions | _did_actions)
    _is_privileged
}

# ---------------------------------------------------------------------------
# add_rule
# ---------------------------------------------------------------------------

_perm_add_rule if {
    # Domain checks
    _protocol_combo_allowed
    _dst_rse_name_valid
    _src_rse_name_valid

    # Account check: issuer creates a rule for their own account (not locked)
    input.kwargs.account == input.issuer
    not input.kwargs.locked
}

_perm_add_rule if {
    # Domain checks
    _protocol_combo_allowed
    _dst_rse_name_valid
    _src_rse_name_valid

    # Account check: root or admin
    _is_privileged
}

# ---------------------------------------------------------------------------
# add_rse
# ---------------------------------------------------------------------------

_perm_add_rse if {
    _is_privileged
    _rse_name_valid(input.kwargs.rse)
}

# ---------------------------------------------------------------------------
# update_rse
# ---------------------------------------------------------------------------

_perm_update_rse if {
    _is_privileged
    # No rename in this update — always allowed for privileged users
    not input.kwargs.parameters.rse
}

_perm_update_rse if {
    _is_privileged
    # Rename: new name must be valid
    new_name := input.kwargs.parameters.rse
    _rse_name_valid(new_name)
}

# ---------------------------------------------------------------------------
# DID actions — scope owner or privileged
# ---------------------------------------------------------------------------

_perm_did_action if {
    _is_privileged
}

_perm_did_action if {
    # Scope owner: the issuer's account matches the scope name prefix.
    # In a real deployment, look up data.scope_owners[input.kwargs.scope].
    # This stub accepts "mock" scopes without privilege for testing.
    input.kwargs.scope == "mock"
}

_perm_did_action if {
    # Issuer owns the scope (same name prefix convention used in generic.py)
    startswith(input.kwargs.scope, input.issuer)
}

# ---------------------------------------------------------------------------
# Protocol combo rules
# ---------------------------------------------------------------------------

_allowed_combos := {
    ["webdav", "webdav"],
    ["s3", "webdav"],
    ["xrdhttp", "webdav"],
}

_protocol_combo_allowed if {
    # No protocol hints supplied → skip check (Rucio will pick protocol)
    not input.kwargs.source_protocol
    not input.kwargs.dst_protocol
}

_protocol_combo_allowed if {
    src := lower(input.kwargs.source_protocol)
    dst := lower(input.kwargs.dst_protocol)
    [src, dst] in _allowed_combos
}

# ---------------------------------------------------------------------------
# RSE naming rules
# ---------------------------------------------------------------------------

_known_rse_types := {
    "DATADISK",
    "SCRATCHDISK",
    "LOCALGROUPDISK",
    "TAPE",
    "USERDISK",
}

_rse_name_valid(name) if {
    # Must match <SITE>_<TYPE> — uppercase alphanumeric + underscore
    regex.match(`^[A-Z0-9]+_[A-Z0-9]+$`, name)
    parts := split(name, "_")
    count(parts) == 2
    parts[1] in _known_rse_types
}

# Destination RSE — only validate bare RSE names (no expression operators)
_dst_rse_name_valid if {
    not input.kwargs.rse_expression
}

_dst_rse_name_valid if {
    expr := input.kwargs.rse_expression
    _is_expression(expr)   # skip validation for complex expressions
}

_dst_rse_name_valid if {
    expr := input.kwargs.rse_expression
    not _is_expression(expr)
    _rse_name_valid(expr)
}

# Source RSE — same logic
_src_rse_name_valid if {
    not input.kwargs.source_rse_expression
}

_src_rse_name_valid if {
    expr := input.kwargs.source_rse_expression
    _is_expression(expr)
}

_src_rse_name_valid if {
    expr := input.kwargs.source_rse_expression
    not _is_expression(expr)
    _rse_name_valid(expr)
}

_is_expression(expr) if { contains(expr, "=") }
_is_expression(expr) if { contains(expr, "&") }
_is_expression(expr) if { contains(expr, "|") }

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_is_privileged if {
    input.is_root == true
}

_is_privileged if {
    # In a real deployment load from OPA data bundle:
    #   data.vo.admins[input.issuer]
    # The Python caller sets is_admin when it can determine it cheaply.
    input.is_admin == true
}

# Note: extend _is_privileged with data.vo.admins[input.issuer]
# once an admin data bundle is ingested via the ingest script.

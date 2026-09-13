package vo.authz.v4

import rego.v1

# Top-level entry point

default allow := false

allow if { _action_allowed }

# Action sets — Phase 4 sets plus _replica_actions (see below)

_rse_actions      := {"add_rse", "update_rse", "del_rse",
                       "add_rse_attribute", "del_rse_attribute"}
_rule_actions     := {"add_rule", "del_rule", "update_rule", "approve_rule"}
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
# hold an admin entitlement rather than have the policy relaxed. The
# Rucio client only requests it when ignore_availability=True is passed
# to add_replicas.
_replica_actions  := {"add_replicas", "update_replicas_states", "delete_replicas"}

_all_known_actions := _rule_actions | _rse_actions | _did_actions |
                      _protocol_actions | _replica_actions

# Dispatch

_action_allowed if { input.action == "add_rule";                                      _perm_add_rule }
_action_allowed if { input.action in {"del_rule", "update_rule"};                     _perm_rule_owner_or_privileged }
_action_allowed if { input.action == "approve_rule";                                  _is_privileged }
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
}

_perm_add_rule if {
    _dst_rse_name_valid
    _src_rse_name_valid
    _is_privileged
}

# del_rule / update_rule — owner self-service

_perm_rule_owner_or_privileged if { input.kwargs.account == input.issuer }
_perm_rule_owner_or_privileged if { _is_privileged }

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
# signal to gate on. The non-privileged path is therefore opt-in via the
# bundle: set data.vo.policy.allow_replica_writes_to_allowlisted_rses to
# true to let any authenticated account register replicas on an
# allowlisted RSE. Default is privileged-only.
#
# Phase 5 has no RSE-name allowlist in its bundle, so _rse_name_valid here
# means the NAME_TYPE naming convention.

_perm_add_replicas if { _is_privileged }

_perm_add_replicas if {
    data.vo.policy.allow_replica_writes_to_allowlisted_rses == true
    _rse_name_valid(input.kwargs.rse)
}

# DID actions

_perm_did_action if { _is_privileged }
_perm_did_action if { input.kwargs.scope == "mock" }

# NOTE: startswith, not equality — an issuer "d" matches scope "ddmlab".
# Left as-is because phase 4 and phase 6 share this shape and the e2e
# input documents rely on it; tightening it to == (or to a scope_owner
# lookup) is a deliberate policy change to be made across all phases at
# once.
_perm_did_action if { startswith(input.kwargs.scope, input.issuer) }

_perm_did_action if {
    input.action == "attach_dids_to_dids"
    attachment := input.kwargs.attachments[_]
    startswith(attachment.scope, input.issuer)
}

# add_dids passes a list of DIDs and no top-level scope, so the clause
# above can never match it — it was silently falling through to
# privileged-only despite being listed in _did_actions. Every DID in the
# batch must be in a scope the issuer owns.
_perm_did_action if {
    input.action == "add_dids"
    count(input.kwargs.dids) > 0
    every did in input.kwargs.dids {
        startswith(did.scope, input.issuer)
    }
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


default _is_privileged := false

# Bootstrap: root account has no OIDC token — allow unconditionally.
_is_privileged if { input.issuer == "root" }

# OIDC path: any entitlement that maps to "admin" grants privilege.
# Only "admin" is consulted — a "user" mapping in the bundle is
# documentation rather than policy, since non-admin accounts reach the same
# self-service clauses as an account with no entitlements at all.
_is_privileged if {
    entitlement := input.token.entitlements[_]
    _entitlement_privilege(entitlement) == "admin"
}

# Bundle-driven entitlement policy. When a bundle IS loaded this is the
# only source of privilege — the fallback below does not apply, so the
# bundle must contain the rucio-admins URN or admin tokens will be denied.
_entitlement_privilege(entitlement) := level if {
    level := data.vo.entitlement_policy[entitlement]
}

# Hardcoded fallback — used when no bundle is loaded (CI / testing).
_entitlement_privilege(entitlement) := "admin" if {
    not data.vo.entitlement_policy
    entitlement in {
        "urn:example:aai.example.org:group:rucio-admins:role=member",
        "urn:example:aai.example.org:group:atlas-production:role=member",
    }
}

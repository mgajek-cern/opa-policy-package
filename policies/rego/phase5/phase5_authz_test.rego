# Unit tests for vo.authz.v4 — run with `opa test policies/rego -v`.
#
# Decision logic only: no stack, no bundle. Data the deployed bundle would
# carry is injected per test with `with data.vo...`; without it the Rego's
# hardcoded fallbacks apply.
package vo.authz.v4_test

import rego.v1

_admin := "urn:example:aai.example.org:group:rucio-admins:role=member"

_user := "urn:example:aai.example.org:group:rucio-users:role=member"

_atlas_prod := "urn:example:aai.example.org:group:atlas-production:role=member"

_atlas_user := "urn:example:aai.example.org:group:atlas-users:role=member"

_cms_prod := "urn:example:aai.example.org:group:cms-production:role=member"

_unmapped := "urn:example:aai.example.org:group:unknown:role=member"

_mfa := "https://refeds.org/profile/mfa"

_rule_id := "1f0e3dad99908345f7439f8ffabdffc4"

_owned := "alice.data"

_unnamed := "projectdata"

_foreign := "bob.data"

_prefixed := "alice.dataleak"

# ── Helpers ─────────────────────────────────────────────────────────────

_ok(issuer, action, claims, kwargs) if {
	data.vo.authz.v4.allow with input as {
		"issuer": issuer, "action": action,
		"token": {"entitlements": claims}, "kwargs": kwargs,
	}
}

_ok_acr(issuer, action, claims, acr, kwargs) if {
	data.vo.authz.v4.allow with input as {
		"issuer": issuer, "action": action,
		"token": {"entitlements": claims, "acr": acr}, "kwargs": kwargs,
	}
}

_root_ok(action, kwargs) if _ok("root", action, [], kwargs)

_user_rule(dids, owned, extra) := object.union(
	{"account": "alice", "locked": false, "rse_expression": "CERN_DATADISK", "dids": dids, "owned_scopes": owned},
	extra,
)

_update(extra) := object.union({"rule_id": _rule_id}, extra)

# ── Privilege from claims ───────────────────────────────────────────────

test_admin_grants_del_rse if _ok("adminuser", "del_rse", [_admin], {})

test_user_denied_del_rse if not _ok("alice", "del_rse", [_user], {})

test_no_claims_denied_privileged if not _ok("alice", "del_rse", [], {})

test_atlas_production_is_admin if _ok("prod", "add_rse", [_atlas_prod], {"rse": "CERN_DATADISK"})

test_atlas_users_is_not_admin if not _ok("alice", "add_rse", [_atlas_user], {"rse": "CERN_DATADISK"})

test_any_admin_claim_grants if _ok("adminuser", "del_rse", [_atlas_prod, _admin], {})

test_user_claims_together_grant_nothing if not _ok("alice", "del_rse", [_user, _atlas_user], {})

test_naming_rule_blocks_admin if {
	not _ok("adminuser", "add_rule", [_admin], {"account": "adminuser", "locked": false, "rse_expression": "cern_bad"})
}

# ── Authentication context (acr) ────────────────────────────────────────

test_acr_ignored_when_not_required if {
	_ok_acr("adminuser", "del_rse", [_admin], _mfa, {})
	_ok("adminuser", "del_rse", [_admin], {})
}

test_acr_match_allows if _ok_acr("adminuser", "del_rse", [_admin], _mfa, {}) with data.vo.policy.required_acr as _mfa

test_acr_missing_denies if not _ok("adminuser", "del_rse", [_admin], {}) with data.vo.policy.required_acr as _mfa

test_acr_differs_denies if {
	not _ok_acr("adminuser", "del_rse", [_admin], "urn:mace:incommon:iap:silver", {}) with data.vo.policy.required_acr as _mfa
}

test_root_unaffected_by_acr if _root_ok("del_rse", {}) with data.vo.policy.required_acr as _mfa

test_rule_self_service_unaffected_by_acr if {
	_ok("alice", "del_rule", [_user], {"rule_id": _rule_id, "rule_owner": "alice"}) with data.vo.policy.required_acr as _mfa
}

test_scope_ownership_unaffected_by_acr if {
	_ok("alice", "add_did", [_user], {"scope": _owned, "name": "f", "owned_scopes": [_owned]}) with data.vo.policy.required_acr as _mfa
}

# ── DID self-service ────────────────────────────────────────────────────

test_did_owned_scope if _ok("alice", "add_did", [_user], {"scope": _owned, "name": "f", "owned_scopes": [_owned]})

test_did_other_scope_denied if not _ok("alice", "add_did", [_user], {"scope": _foreign, "name": "f", "owned_scopes": [_owned]})

test_add_dids_requires_every_scope if {
	_ok("alice", "add_dids", [_user], {"dids": [{"scope": _owned, "name": "f1"}, {"scope": _unnamed, "name": "f2"}], "owned_scopes": [_owned, _unnamed]})
	not _ok("alice", "add_dids", [_user], {"dids": [{"scope": _owned, "name": "f1"}, {"scope": _foreign, "name": "f2"}], "owned_scopes": [_owned]})
}

test_del_protocol_without_scheme if {
	_ok("adminuser", "del_protocol", [_admin], {})
	not _ok("alice", "del_protocol", [_user], {})
}

# ── add_rule: rule ownership AND data ownership (design-004) ────────────

test_add_rule_own_rule_own_data if _ok("alice", "add_rule", [_user], _user_rule([{"scope": _owned, "name": "f1"}], [_owned], {}))

test_add_rule_owned_unnamed_scope if _ok("alice", "add_rule", [_user], _user_rule([{"scope": _unnamed, "name": "f1"}], [_unnamed], {}))

test_add_rule_foreign_data_denied if not _ok("alice", "add_rule", [_user], _user_rule([{"scope": _foreign, "name": "f1"}], [], {}))

test_add_rule_prefix_foreign_denied if not _ok("alice", "add_rule", [_user], _user_rule([{"scope": _prefixed, "name": "f1"}], [_owned], {}))

test_add_rule_one_foreign_did_denied if {
	not _ok("alice", "add_rule", [_user], _user_rule([{"scope": _owned, "name": "f1"}, {"scope": _foreign, "name": "f2"}], [_owned], {}))
}

test_add_rule_empty_dids_denied if not _ok("alice", "add_rule", [_user], _user_rule([], [_owned], {}))

test_add_rule_locked_denied if not _ok("alice", "add_rule", [_user], _user_rule([{"scope": _owned, "name": "f1"}], [_owned], {"locked": true}))

test_add_rule_other_account_denied if {
	not _ok("alice", "add_rule", [_user], _user_rule([{"scope": _owned, "name": "f1"}], [_owned], {"account": "bob"}))
}

test_add_rule_admin_foreign_data if {
	_ok("adminuser", "add_rule", [_admin], {"account": "adminuser", "locked": false, "rse_expression": "CERN_DATADISK", "dids": [{"scope": _foreign, "name": "f1"}], "owned_scopes": []})
}

# ── del_rule / update_rule: facts from the rules table ──────────────────

test_owner_deletes_own_rule if _ok("alice", "del_rule", [_user], {"rule_id": _rule_id, "rule_owner": "alice"})

test_non_owner_delete_denied if not _ok("alice", "del_rule", [_user], {"rule_id": _rule_id, "rule_owner": "bob"})

test_unresolvable_rule_delete_denied if not _ok("alice", "del_rule", [_user], {"rule_id": _rule_id})

test_admin_deletes_any_rule if _ok("adminuser", "del_rule", [_admin], {"rule_id": _rule_id, "rule_owner": "bob"})

test_owner_updates_own_rule if {
	_ok("alice", "update_rule", [_user], _update({"options": {"lifetime": 3600}, "rule_owner": "alice", "rule_scope": _owned, "owned_scopes": [_owned]}))
}

test_owner_update_unowned_scope_denied if {
	not _ok("alice", "update_rule", [_user], _update({"options": {"lifetime": 3600}, "rule_owner": "alice", "rule_scope": _foreign, "owned_scopes": [_owned]}))
}

test_update_without_options_allowed if {
	_ok("alice", "update_rule", [_user], _update({"rule_owner": "alice", "rule_scope": _owned, "owned_scopes": [_owned]}))
}

test_reassignment_denied_for_owner if {
	not _ok("alice", "update_rule", [_user], _update({"options": {"account": "bob"}, "rule_owner": "alice", "rule_scope": _owned, "owned_scopes": [_owned]}))
}

test_reassignment_to_self_denied if {
	not _ok("alice", "update_rule", [_user], _update({"options": {"account": "alice"}, "rule_owner": "alice", "rule_scope": _owned, "owned_scopes": [_owned]}))
}

test_reassignment_allowed_for_admin if {
	_ok("adminuser", "update_rule", [_admin], _update({"options": {"account": "bob"}, "rule_owner": "alice", "rule_scope": _owned, "owned_scopes": []}))
}

test_unresolvable_rule_update_denied if {
	not _ok("alice", "update_rule", [_user], _update({"options": {"lifetime": 3600}, "owned_scopes": [_owned]}))
}

test_reduce_and_move_rule_privileged_only if {
	not _ok("alice", "reduce_rule", [_user], {"rule_id": _rule_id})
	_ok("adminuser", "reduce_rule", [_admin], {"rule_id": _rule_id})
	not _ok("alice", "move_rule", [_user], {"rule_id": _rule_id})
	_ok("adminuser", "move_rule", [_admin], {"rule_id": _rule_id})
}

# ── add_replicas: user tier, no file scopes in this phase ───────────────

test_add_replicas_admin if _ok("adminuser", "add_replicas", [_admin], {"rse": "CERN_DATADISK"})

test_add_replicas_user_tier_valid_rse if _ok("alice", "add_replicas", [_user], {"rse": "CERN_DATADISK"})

test_add_replicas_user_tier_bad_rse_denied if not _ok("alice", "add_replicas", [_user], {"rse": "cern_bad"})

test_add_replicas_no_claims_denied if not _ok("nobody", "add_replicas", [], {"rse": "CERN_DATADISK"})

test_add_replicas_unmapped_denied if not _ok("nobody", "add_replicas", [_unmapped], {"rse": "CERN_DATADISK"})

test_delete_replicas_privileged_only if {
	_ok("adminuser", "delete_replicas", [_admin], {"rse": "CERN_DATADISK"})
	not _ok("alice", "delete_replicas", [_user], {"rse": "CERN_DATADISK"})
}

# ── Root bootstrap ──────────────────────────────────────────────────────

test_root_bootstrap if {
	_root_ok("del_rse", {})
	_root_ok("add_rse", {"rse": "CERN_DATADISK"})
	_root_ok("some_unknown_action", {})
	_root_ok("add_did", {"scope": _foreign, "name": "d"})
	_root_ok("del_rule", {"rule_id": _rule_id})
}

test_root_blocked_by_naming_rule if not _root_ok("add_rule", {"account": "root", "locked": false, "rse_expression": "cern_bad"})

# ── Bundle-driven claim policy ──────────────────────────────────────────

test_bundle_custom_claim if {
	_ok("cmsuser", "del_rse", [_cms_prod], {}) with data.vo.entitlement_policy as {_cms_prod: "admin", _user: "user"}
}

test_bundle_removed_claim_loses_privilege if {
	not _ok("adminuser", "del_rse", [_admin], {}) with data.vo.entitlement_policy as {_atlas_prod: "admin"}
	_ok("prod", "del_rse", [_atlas_prod], {}) with data.vo.entitlement_policy as {_atlas_prod: "admin"}
}

test_bundle_user_tier_reaches_add_replicas if {
	_ok("alice", "add_replicas", [_user], {"rse": "CERN_DATADISK"}) with data.vo.entitlement_policy as {_admin: "admin", _user: "user"}
	not _ok("alice", "add_replicas", [_unmapped], {"rse": "CERN_DATADISK"}) with data.vo.entitlement_policy as {_admin: "admin", _user: "user"}
}

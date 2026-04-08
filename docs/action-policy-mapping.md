# Action → Policy Mapping

This document maps every action key from Rucio's `has_permission()` dispatch
table (`lib/rucio/core/permission/generic.py`) to its policy treatment in this
package.

**Legend**

| Symbol | Meaning |
|--------|---------|
| ✅ | Implemented — custom logic in Phase 1 (Python) and Phase 2 (Rego) |
| 🔒 | Privileged-only fallback — root or admin, no extra domain checks |
| 🔲 | Not delegated — falls through to Rucio's built-in generic handler |
| 💡 | Recommended for future delegation |

---

## Replication rules

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `add_rule` | ✅ Custom | ✅ `_perm_add_rule` | Protocol combo + RSE naming + account ownership check. Core of the TPC policy. |
| `del_rule` | 🔒 Fallback | 🔒 `_is_privileged` | Privileged-only. 💡 Could add: issuer == rule owner allows self-deletion. |
| `update_rule` | 🔒 Fallback | 🔒 `_is_privileged` | Privileged-only. 💡 Could mirror `del_rule` — rule owner should be able to update their own. |
| `approve_rule` | 🔒 Fallback | 🔒 `_is_privileged` | Approval workflow — privileged-only is appropriate. |
| `reduce_rule` | 🔲 Generic | 🔲 Not delegated | 💡 Low priority. Could restrict to rule owner or privileged. |
| `move_rule` | 🔲 Generic | 🔲 Not delegated | 💡 Involves RSE naming — worth delegating to validate destination RSE name. |

---

## RSE management

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `add_rse` | ✅ Custom | ✅ `_perm_add_rse` | Privileged + RSE naming convention enforced. |
| `update_rse` | ✅ Custom | ✅ `_perm_update_rse` | Privileged + RSE naming enforced on rename. |
| `del_rse` | 🔒 Fallback | 🔒 `_is_privileged` | Privileged-only. Appropriate — deletion is destructive. |
| `add_rse_attribute` | 🔒 Fallback | 🔒 `_is_privileged` | Privileged-only. 💡 Could add attribute-key allowlist (e.g. block setting `admin` directly). |
| `del_rse_attribute` | 🔒 Fallback | 🔒 `_is_privileged` | Privileged-only. Same recommendation as `add_rse_attribute`. |
| `add_protocol` | 🔲 Generic | 🔲 Not delegated | 💡 Worth delegating — could enforce allowed protocol schemes (davs, s3, https). |
| `del_protocol` | 🔲 Generic | 🔲 Not delegated | 💡 Pair with `add_protocol` if delegated. |
| `update_protocol` | 🔲 Generic | 🔲 Not delegated | 💡 Pair with `add_protocol` if delegated. |
| `add_qos_policy` | 🔲 Generic | 🔲 Not delegated | Low priority. Privileged-only in generic is fine. |
| `delete_qos_policy` | 🔲 Generic | 🔲 Not delegated | Low priority. Privileged-only in generic is fine. |
| `set_rse_usage` | 🔲 Generic | 🔲 Not delegated | Internal daemon action. Leave as generic. |
| `set_rse_limits` | 🔲 Generic | 🔲 Not delegated | Internal daemon action. Leave as generic. |
| `list_transfer_limits` | 🔲 Generic | 🔲 Not delegated | Read-only list. Low sensitivity. |
| `set_transfer_limit` | 🔲 Generic | 🔲 Not delegated | 💡 Could enforce per-VO or per-RSE caps via OPA data bundle. |
| `delete_transfer_limit` | 🔲 Generic | 🔲 Not delegated | Pair with `set_transfer_limit` if delegated. |

---

## Data Identifiers (DIDs)

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `add_did` | 🔲 Generic | ✅ `_perm_did_action` | Phase 2: scope-owner or privileged. Phase 1 defers to generic. 💡 Phase 1 should be aligned. |
| `add_dids` | 🔲 Generic | ✅ `_perm_did_action` | Bulk version of `add_did`. Same note. |
| `attach_dids` | 🔲 Generic | ✅ `_perm_did_action` | Scope-owner or privileged in Phase 2. |
| `detach_dids` | 🔲 Generic | ✅ `_perm_did_action` | Scope-owner or privileged in Phase 2. |
| `attach_dids_to_dids` | 🔲 Generic | 🔲 Not delegated | 💡 Semantically identical to `attach_dids` — should be added to `_did_actions` in Rego. |
| `create_did_sample` | 🔲 Generic | 🔲 Not delegated | 💡 Low priority. Scope-owner check would be consistent with other DID actions. |
| `set_metadata` | 🔲 Generic | 🔲 Not delegated | 💡 Could restrict metadata keys to an allowlist via OPA data bundle. |
| `set_metadata_bulk` | 🔲 Generic | 🔲 Not delegated | Bulk version of `set_metadata`. Pair if delegated. |
| `set_status` | 🔲 Generic | 🔲 Not delegated | 💡 Setting OBSOLETE is destructive — worth a privileged-only check. |
| `resurrect` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `remove_did_from_followed` | 🔲 Generic | 🔲 Not delegated | Low sensitivity — issuer should only be able to unfollow their own subscriptions. |
| `remove_dids_from_followed` | 🔲 Generic | 🔲 Not delegated | Bulk version of above. |

---

## Replicas

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `add_replicas` | 🔲 Generic | 🔲 Not delegated | Internal conveyor/daemon action. Leave as generic. |
| `delete_replicas` | 🔲 Generic | 🔲 Not delegated | 💡 Destructive — could restrict to privileged or RSE admin. |
| `update_replicas_states` | 🔲 Generic | 🔲 Not delegated | Internal daemon action. Leave as generic. |
| `declare_bad_file_replicas` | 🔲 Generic | 🔲 Not delegated | 💡 Could restrict to a `checker` role to prevent abuse. |
| `declare_suspicious_file_replicas` | 🔲 Generic | 🔲 Not delegated | Same as `declare_bad_file_replicas`. |
| `skip_availability_check` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `add_bad_pfns` | 🔲 Generic | 🔲 Not delegated | 💡 Same as `declare_bad_file_replicas`. |

---

## Accounts and identities

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `add_account` | 🔲 Generic | 🔲 Not delegated | 💡 Could enforce account naming convention (e.g. no uppercase). |
| `del_account` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `update_account` | 🔲 Generic | 🔲 Not delegated | 💡 Issuer should be allowed to update their own account details. |
| `add_account_identity` | 🔲 Generic | 🔲 Not delegated | 💡 Issuer should be allowed to add identities to their own account. |
| `del_account_identity` | 🔲 Generic | 🔲 Not delegated | Same as `add_account_identity`. |
| `del_identity` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `add_attribute` | 🔲 Generic | 🔲 Not delegated | 💡 If `admin` attribute is sensitive, delegate and block self-granting. |
| `del_attribute` | 🔲 Generic | 🔲 Not delegated | Pair with `add_attribute` if delegated. |
| `add_scope` | 🔲 Generic | 🔲 Not delegated | 💡 Could enforce scope naming (e.g. must start with account name). |
| `list_heartbeats` | 🔲 Generic | 🔲 Not delegated | Read-only. Low sensitivity. |

---

## Subscriptions

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `add_subscription` | 🔲 Generic | 🔲 Not delegated | 💡 Subscription filter DID expressions could embed RSE expressions — worth validating RSE naming here too. |
| `update_subscription` | 🔲 Generic | 🔲 Not delegated | Same as `add_subscription`. |

---

## Authentication tokens

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `get_auth_token_user_pass` | 🔲 Generic | 🔲 Not delegated | Auth mechanism — do not delegate. |
| `get_auth_token_gss` | 🔲 Generic | 🔲 Not delegated | Auth mechanism — do not delegate. |
| `get_auth_token_x509` | 🔲 Generic | 🔲 Not delegated | Auth mechanism — do not delegate. |
| `get_auth_token_saml` | 🔲 Generic | 🔲 Not delegated | Auth mechanism — do not delegate. |
| `get_auth_token_ssh` | 🔲 Generic | 🔲 Not delegated | Auth mechanism — do not delegate. |
| `get_signed_url` | 🔲 Generic | 🔲 Not delegated | 💡 Could restrict to specific RSEs or protocol schemes. |

---

## Transfers and requests

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `queue_requests` | 🔲 Generic | 🔲 Not delegated | Internal conveyor action. Leave as generic. |
| `get_request_by_did` | 🔲 Generic | 🔲 Not delegated | Read-only. Issuer should only see their own unless privileged. 💡 Low priority. |
| `get_request_history_by_did` | 🔲 Generic | 🔲 Not delegated | Same as `get_request_by_did`. |
| `cancel_request` | 🔲 Generic | 🔲 Not delegated | 💡 Issuer should be allowed to cancel their own requests. |
| `get_next` | 🔲 Generic | 🔲 Not delegated | Internal conveyor polling. Leave as generic. |
| `list_requests` | 🔲 Generic | 🔲 Not delegated | 💡 Non-privileged users should only see their own requests. |
| `list_requests_history` | 🔲 Generic | 🔲 Not delegated | Same as `list_requests`. |

---

## Account limits

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `set_local_account_limit` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `set_global_account_limit` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `delete_local_account_limit` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `delete_global_account_limit` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. |
| `get_local_account_usage` | 🔲 Generic | 🔲 Not delegated | 💡 Issuer should be allowed to read their own usage without privilege. |
| `get_global_account_usage` | 🔲 Generic | 🔲 Not delegated | Same as `get_local_account_usage`. |

---

## Configuration

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `config_sections` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate. Config is sensitive. |
| `config_add_section` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_has_section` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_options` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_has_option` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_get` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_items` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_set` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_remove_section` | 🔲 Generic | 🔲 Not delegated | Same. |
| `config_remove_option` | 🔲 Generic | 🔲 Not delegated | Same. |

---

## Lifetime exceptions and export

| Action | Phase 1 | Phase 2 (Rego) | Notes |
|--------|---------|----------------|-------|
| `update_lifetime_exceptions` | 🔲 Generic | 🔲 Not delegated | 💡 Could restrict to the requesting account's own exceptions. |
| `export` | 🔲 Generic | 🔲 Not delegated | Privileged-only in generic is appropriate — exports can contain sensitive RSE/account data. |

---

## Cross-reference: `rucio-it-tools` caller perspective

`rucio-it-tools` (`gitlab.cern.ch/rucio-it/rucio-tools`) ships only LFN2PFN
algorithms (`rucio_it_sme_policy`) and no `has_permission()` override. All
permission decisions for its API calls fall entirely to whichever policy package
is deployed — making the gap analysis below directly actionable.

The tools run as a **service account** (non-root, non-admin unless explicitly
granted the `admin` attribute), so gaps here can silently block production
registration workflows.

| Tool | Rucio client call | `has_permission()` action | Coverage | Note |
|------|-------------------|--------------------------|----------|------|
| `rucio_it_register.py` | `client.add_replicas()` | `add_replicas` | 🔲 Generic | Permissive enough in practice |
| `rucio_it_register.py` | `client.add_container()` / `add_dataset()` | `add_did` | Phase 1: 🔲 Generic · Phase 2: ✅ | Phase 1/2 inconsistency |
| `rucio_it_register.py` | `client.attach_dids_to_dids()` | `attach_dids_to_dids` | 🔲 Not delegated | **Gap** — called on every file registration |
| `rucio_it_register.py` | `client.add_replication_rule()` | `add_rule` | ✅ Custom (both phases) | Service account must own scope or be privileged |
| `rucio_it_register.py` | `client.set_metadata()` | `set_metadata` | 🔲 Generic | No key allowlist |
| `rucio_it_fetch_pfns.py` | `client.list_replicas()` | _(no gate — list API)_ | n/a | Outside policy package scope |
| `rucio_it_dump_replicas.py` | _(direct psycopg query)_ | _(none — bypasses API)_ | n/a | DB credential controls only |
| `rucio_it_register_redis.py` | _(delegates to `rucio_it_register.py`)_ | _(same as above)_ | — | No additional API calls |

**Gaps that affect production workflows:**

| Action | Urgency | Reason |
|--------|---------|--------|
| `attach_dids_to_dids` | **High** | Called on every file registration; absent from `_did_actions` in Rego |
| `add_did` Phase 1 | **Medium** | Phase 2 has scope-owner check; Phase 1 falls through to generic |
| `set_metadata` | **Low** | Unrestricted key writes; revisit if metadata keys become sensitive |

---

## Recommended next delegations (priority order)

These are the actions where delegating to OPA would add meaningful policy
value beyond what the generic handler already provides, ordered by impact.
Items marked 🔧 are directly required by `rucio-it-tools` registration workflows.

1. 🔧 **`attach_dids_to_dids`** — already semantically covered by `_perm_did_action`
   in Rego; just needs adding to `_did_actions`. Zero new logic required.
   Highest urgency: called on every file registered by `rucio_it_register.py`.

2. 🔧 **`add_did` in Phase 1** — Phase 2 already applies a scope-owner check via
   `_perm_did_action`; Phase 1 falls through to generic. Add `perm_add_did` to
   `permission.py` (Phase 1) using the same scope-prefix logic to remove the
   inconsistency. `add_dids` should be aligned at the same time.

3. **`del_rule` / `update_rule`** — rule owners should be able to manage their
   own rules. Requires OPA to receive the rule's `account` field (already in
   `_PASSTHROUGH_KEYS`).

4. **`add_protocol` / `del_protocol` / `update_protocol`** — enforcing an
   allowlist of permitted schemes (`davs`, `s3`, `https`, `root`) is a natural
   extension of the existing TPC protocol policy. Consistent with the scheme
   choices already used in `rucio-it-tools` RSE setup scripts (`davs`, `root`).

5. **`move_rule`** — the destination RSE expression should pass the same naming
   validation already applied in `add_rule`.

6. **`add_account` / `add_scope`** — naming convention enforcement (mirrors RSE
   naming). Useful for operational consistency.

7. **`add_attribute`** — block self-granting of the `admin` attribute; requires
   checking `kwargs["key"] == "admin"` and `kwargs["account"] == issuer`.

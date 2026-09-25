# Action → Policy Mapping

Maps Rucio's `has_permission()` actions (`lib/rucio/core/permission/generic.py`)
to their current treatment in this package's policy phases.

**Legend:** ✅ Implemented · 🔒 Privileged-only fallback · 🔲 Not delegated (generic handler) · 💡 Recommended for future delegation

`rego/phase6/authz.rego` is authoritative if this table falls behind — it's
shared by both `AUTHZ_MODE` transports (direct and service), so it applies
identically regardless of which one Rucio is configured with. Phases 3–5
sit between phase 1 and phase 6 as shown here; see each phase's own Rego.

| Business operation | Rucio action(s) | Phase 1 | Phase 6 (Rego) | Notes |
|---|---|---|---|---|
| `rule.create` | `add_rule` | ✅ Custom | ✅ `_perm_add_rule` | RSE naming + `account == issuer` + `locked == false`, or privileged. |
| `rule.update` | `update_rule` | 🔒 Fallback | ✅ `_perm_update_rule` | Owner self-service, and owns `rule_scope`; blocked if reassignment (`options.account`) is requested. |
| `rule.delete` | `del_rule` | 🔒 Fallback | ✅ `_perm_del_rule` | Owner self-service. |
| — | `approve_rule` | 🔒 Fallback | 🔒 `_is_privileged` | Approval workflow — privileged-only is correct as-is. |
| `rse.create` | `add_rse` | ✅ Custom | ✅ `_perm_add_rse` | Privileged + naming convention, with a testbed allowlist in the bundle. |
| `rse.update` | `update_rse` | ✅ Custom | ✅ `_perm_update_rse` | Privileged + naming enforced on rename. |
| — | `del_rse` | 🔒 Fallback | 🔒 `_perm_del_rse` | Explicit typed action, privilege-only logic — not the catch-all. |
| — | `add_rse_attribute`, `del_rse_attribute` | 🔒 Fallback | 🔒 `_perm_add_rse_attribute` / `_perm_del_rse_attribute` | Explicit typed actions, privilege-only logic — not the catch-all. 💡 Attribute-key allowlist (block setting `admin` directly). |
| `did.create` | `add_did` | 🔲 Generic | ✅ `_perm_add_did` | Single-DID: `kwargs.scope` must be in `owned_scopes`, or privileged. |
| `did.create` | `add_dids` | 🔲 Generic | ✅ `_perm_add_dids` | Every `did.scope` in the list must be in `owned_scopes` ([design-003](./design/design-003-scope-ownership.md)). |
| `did.attach` | `attach_dids` | 🔲 Generic | ✅ `_perm_attach_dids` | Single-DID: `kwargs.scope` owned, or privileged. |
| `did.attach` | `attach_dids_to_dids` | 🔲 Generic | ✅ `_perm_attach_dids_to_dids` | Every `attachments[].scope` owned, or privileged. |
| `did.detach` | `detach_dids` | 🔲 Generic | ✅ `_perm_detach_dids` | Scope-owner or privileged. |
| `protocol.create/update/delete` | `add_protocol`, `update_protocol`, `del_protocol` | 🔲 Generic | ✅ `_perm_add_protocol` / `_perm_update_protocol` / `_perm_del_protocol` | Privileged + scheme allowlist from `data.vo.policy.allowed_schemes`, one function per action. |
| — | `add_replicas` | 🔲 Generic | ✅ `_perm_add_replicas` | Privileged; or `"user"`-tier entitlement on a name-valid RSE **and every file's scope owned**; or any account on a name-valid RSE when `allow_replica_writes_to_allowlisted_rses` is true (also requires file scopes owned). Requires the gateway patch forwarding `files` into `owned_scopes` ([design-005](./design/design-005-authorization-service-api.md), "Replica ownership: prerequisite"). |
| — | `delete_replicas` | 🔲 Generic | ✅ `_perm_delete_replicas` | Privileged; or `"user"`-tier entitlement with every file's scope owned. No RSE-name check — removing a record needs no naming guard. |
| — | `update_replicas_states` | 🔲 Generic | 🔒 `_is_privileged` (catch-all) | Destructive / daemon-internal — the one replica action still fully privileged-only. |
| — | `skip_availability_check` | 🔲 Generic | 🔒 catch-all | Deliberately privileged-only — remaining blocker for a fully non-privileged transfer path. |
| `transfer.create` | `queue_requests`, `add_rule` | 🔲 Generic | 🔲 Not delegated | Rucio-originated; consumers are Rucio + FTS. |

Every action not listed — and not in `_all_known_actions` — falls through
`_is_known_action` to `_is_privileged`. Roughly 70 of `generic.py`'s
`perm_*` functions never reach a named rule. Invisible while testing as
`root` or with an admin entitlement; visible the moment a non-privileged
account is used.

**Cross-cutting rules, not visible per-row above:**
- Every 🔒 row and the privileged branch of every ✅ row additionally
  requires the token's `acr` claim to equal `data.vo.policy.required_acr`,
  when that key is set. Self-service (`"user"`-tier) clauses are **not**
  gated on `acr`.
- DID and replica ownership (`owned_scopes`) is resolved via
  `is_scope_owner()` in Python before the OPA call, not a name comparison
  — see [design-003](./design/design-003-scope-ownership.md).
- RSE-name validation accepts an explicit allowlist entry, or a
  `NAME_TYPE` pattern where `TYPE` is in `known_rse_types`; both are
  data-driven with hardcoded fallbacks when the bundle isn't loaded.

**Not delegated, reviewed and left as-is unless noted:**

| Area | Status | 💡 if revisited |
|---|---|---|
| Bad-PFN / suspicious-replica declarations | privileged-only | gate on a `checker` role |
| `update_account`, `add_account_identity` | privileged-only | allow self-service |
| `add_account`, `add_scope` | privileged-only | naming-convention checks |
| `add_subscription` | privileged-only | validate embedded RSE expressions |
| Auth token issuance | privileged-only | never delegate — auth mechanism, not authorization |
| `list_requests`, `cancel_request` | privileged-only | scope to the issuer's own unless privileged |
| Account limits | privileged-only | usage *reads* could be self-service |
| Config, lifetime-exceptions/export | privileged-only | none — correct as-is |

## Authorization Service contract

Superseded by [design-005](./design/design-005-authorization-service-api.md):
one typed endpoint per operation (`POST /v1/decisions/rules/create`, etc.),
not a single `/v1/authorize` with a free-form `operation` field. See
design-005's operation catalogue for the current request/response shapes.

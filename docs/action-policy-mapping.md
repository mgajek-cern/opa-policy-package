# Action → Policy Mapping

Maps Rucio's `has_permission()` actions (`lib/rucio/core/permission/generic.py`)
to (a) their current treatment in this package's policy phases, and (b) the
business-oriented operations exposed by the WP4 Authorization Service.

**Legend:** ✅ Implemented · 🔒 Privileged-only fallback · 🔲 Not delegated (generic handler) · 💡 Recommended for future delegation


## Layer 1 — Business operation → Rucio action → phase coverage

The Authorization Service (`POST /v1/authorize`) exposes operations like
`rule.create`; internally these map to one or more Rucio `has_permission()`
actions, which this package's Rego/Python evaluates per phase.

Phase 6 is the current reference; `rego/phase6/authz.rego` is authoritative
if this table falls behind. Phases 3–5 sit between the two columns shown —
see each phase's own Rego.

| Business operation | Rucio action(s) | Phase 1 | Phase 6 (Rego) | Notes |
|---|---|---|---|---|
| `rule.create` | `add_rule` | ✅ Custom | ✅ `_perm_add_rule` | RSE naming + `account == issuer` + `locked == false`, or privileged. Protocol-combo check dropped — Rucio core resolves TPC feasibility per-RSE. |
| `rule.update` | `update_rule` | 🔒 Fallback | ✅ `_perm_rule_owner_or_privileged` | Owner self-service. |
| `rule.delete` | `del_rule` | 🔒 Fallback | ✅ `_perm_rule_owner_or_privileged` | Owner self-service. |
| — | `approve_rule` | 🔒 Fallback | 🔒 `_is_privileged` | Approval workflow — privileged-only is correct as-is. |
| `rse.create` | `add_rse` | ✅ Custom | ✅ `_perm_add_rse` | Privileged + naming convention, with a testbed allowlist in the bundle. |
| `rse.update` | `update_rse` | ✅ Custom | ✅ `_perm_update_rse` | Privileged + naming enforced on rename. |
| — | `del_rse`, `add/del_rse_attribute` | 🔒 Fallback | 🔒 `_is_privileged` | Destructive — privileged-only. 💡 Attribute-key allowlist (block setting `admin` directly). |
| `did.create` | `add_did`, `add_dids` | 🔲 Generic | ✅ `_perm_did_action` | Scope-owner or privileged. `add_dids` carries a DID list and no top-level scope, so it has its own clause: every `did.scope` must start with the issuer. **Phase 1 inconsistency** — Phase 1 should adopt the scope-owner check. |
| `did.attach` | `attach_dids`, `attach_dids_to_dids` | 🔲 Generic | ✅ `_perm_did_action` | Both covered; `attach_dids_to_dids` checks `attachments[_].scope`. |
| `did.detach` | `detach_dids` | 🔲 Generic | ✅ `_perm_did_action` | Scope-owner or privileged. |
| `protocol.update` | `add_protocol`, `update_protocol`, `del_protocol` | 🔲 Generic | ✅ `_perm_protocol_action` | Privileged + scheme allowlist from `data.vo.policy.allowed_schemes`. |
| — | `add_replicas` | 🔲 Generic | ✅ `_perm_add_replicas` | Privileged, or any account on an allowlisted RSE when `data.vo.policy.allow_replica_writes_to_allowlisted_rses` is true. kwargs carry no scope, so there is no ownership signal to gate on. |
| — | `update_replicas_states`, `delete_replicas` | 🔲 Generic | 🔒 `_is_privileged` | Destructive / daemon-internal. |
| — | `skip_availability_check` | 🔲 Generic | 🔒 catch-all | Deliberately privileged-only: Rucio treats it as an admin escalation. Requested by `add_replicas` under `ignore_availability=True`, so it is the remaining blocker for a fully non-privileged transfer path. |
| `transfer.create` | `queue_requests`, `add_rule` | 🔲 Generic | 🔲 Not delegated | Rucio-originated; consumers are Rucio + FTS. |
| `transfer.authorize` | *(none — see below)* | — | — | New, token-centric. Not a Rucio action. |

Every action not listed falls through the `_is_known_action` catch-all to `_is_privileged` — roughly 70 of `generic.py`'s `perm_*` functions. That is invisible while a caller authenticates as `root` or holds an admin entitlement, and becomes visible the moment a non-privileged account is used.

**Reviewed, no change recommended unless noted:** bad-PFN and suspicious-replica declarations (💡 could gate on a `checker` role), accounts/identities (💡 `update_account`, `add_account_identity` should allow self-service; 💡 `add_account`/`add_scope` could get naming-convention checks), subscriptions (💡 `add_subscription` could validate embedded RSE expressions), auth token issuance (never delegate — auth mechanism, not authorization), transfers/requests (💡 `list_requests`, `cancel_request` should scope to the issuer's own unless privileged), account limits (privileged-only is correct; 💡 usage *reads* could be self-service), config and lifetime-exceptions/export (privileged-only is correct).


## Layer 2 — Authorization Service contract

`POST /v1/authorize` serves two request shapes:

```json
// Rucio (group/scope-centric)
{
  "operation": "rule.create",
  "subject": { "id": "alice", "groups": ["/atlas/production"] },
  "resource": { "scope": "alice", "sourceRse": "SRC", "destinationRse": "DST" },
  "context": { "protocol": "davs" }
}
```

```json
// IAM, on behalf of a storage endpoint (token-centric)
{
  "operation": "transfer.authorize",
  "subject": {
    "id": "alice",
    "token": { "sub": "alice", "aud": "dst-se.example.org",
               "iss": "https://e-infra-aai.example.org", "scope": ["write:MUSICA"] }
  },
  "resource": { "destinationRse": "DST", "path": "/MUSICA/alice/dataset123" },
  "context": { "protocol": "davs", "direction": "destination" }
}
```

Response, either shape: `{ "decision": "ALLOW", "reason": "scope owner" }`

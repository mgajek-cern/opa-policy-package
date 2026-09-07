# Action → Policy Mapping

Maps Rucio's `has_permission()` actions (`lib/rucio/core/permission/generic.py`)
to (a) their current treatment in this package's policy phases, and (b) the
business-oriented operations exposed by the WP4 Authorization Service.

**Legend:** ✅ Implemented · 🔒 Privileged-only fallback · 🔲 Not delegated (generic handler) · 💡 Recommended for future delegation

---

## Layer 1 — Business operation → Rucio action → phase coverage

The Authorization Service (`POST /v1/authorize`) exposes operations like
`rule.create`; internally these map to one or more Rucio `has_permission()`
actions, which this package's Rego/Python evaluates per phase.

| Business operation | Rucio action(s) | Phase 1 | Phase 2 (Rego) | Notes |
|---|---|---|---|---|
| `rule.create` | `add_rule` | ✅ Custom | ✅ `_perm_add_rule` | RSE naming + account ownership. Protocol-combo check dropped — Rucio core already resolves TPC feasibility per-RSE. |
| `rule.update` | `update_rule` | 🔒 Fallback | 🔒 `_is_privileged` | 💡 Mirror `del_rule` — owner should update their own. |
| `rule.delete` | `del_rule` | 🔒 Fallback | 🔒 `_is_privileged` | 💡 Owner self-deletion; `account` already in `_PASSTHROUGH_KEYS`. |
| — | `approve_rule` | 🔒 Fallback | 🔒 `_is_privileged` | Approval workflow — privileged-only is correct as-is. |
| `rse.create` | `add_rse` | ✅ Custom | ✅ `_perm_add_rse` | Privileged + naming convention. |
| `rse.update` | `update_rse` | ✅ Custom | ✅ `_perm_update_rse` | Privileged + naming enforced on rename. |
| — | `del_rse`, `add/del_rse_attribute` | 🔒 Fallback | 🔒 `_is_privileged` | Destructive — privileged-only. 💡 Attribute-key allowlist (block setting `admin` directly). |
| `did.create` | `add_did`, `add_dids` | 🔲 Generic | ✅ `_perm_did_action` | **Phase 1/2 inconsistency** — Phase 1 should adopt Phase 2's scope-owner check. |
| `did.attach` | `attach_dids`, `attach_dids_to_dids` | 🔲 Generic | ⚠️ mixed | `attach_dids` ✅; `attach_dids_to_dids` **not yet in `_did_actions`** despite identical semantics. |
| `did.detach` | `detach_dids` | 🔲 Generic | ✅ `_perm_did_action` | Scope-owner or privileged. |
| `protocol.update` | `add_protocol`, `update_protocol`, `del_protocol` | 🔲 Generic | 🔲 Not delegated | 💡 Enforce scheme allowlist (`davs`, `s3`, `https`, `root`, `xrdhttp`) via OPA data bundle. |
| `transfer.create` | `queue_requests`, `add_rule` | 🔲 Generic | 🔲 Not delegated | Rucio-originated; consumers are Rucio + FTS. |
| `transfer.authorize` | *(none — see below)* | — | — | New, token-centric. Not a Rucio action. |

**Not delegated anywhere, left to Rucio's generic handler** — reviewed, no
change recommended unless noted: replicas (`add_replicas`, `delete_replicas`,
`update_replicas_states`, bad-PFN/suspicious-replica declarations — mostly
internal daemon actions; 💡 `delete_replicas` and bad-replica declarations
could gate on a `checker`/privileged role), accounts/identities (💡
`update_account`, `add_account_identity` should allow self-service; 💡
`add_account`/`add_scope` could get naming-convention checks), subscriptions
(💡 `add_subscription` could validate embedded RSE expressions), auth token
issuance (never delegate — auth mechanism, not authorization), transfers/requests
(💡 `list_requests`, `cancel_request` should scope to the issuer's own unless
privileged), account limits (privileged-only is correct; 💡 usage *reads*
could be self-service), config and lifetime-exceptions/export (privileged-only
is correct — sensitive by nature).

---

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

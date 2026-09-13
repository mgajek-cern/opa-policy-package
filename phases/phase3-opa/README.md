# rucio-opa-v2-policy

Phase 3 — OPA as PDP, data-driven configuration, broader action coverage. Policy bundle (`data.vo.policy`) is pushed at deploy time via `ingest_policies.py`. Rego falls back to hardcoded defaults when no bundle is loaded.

## What's new in Phase 3

| Addition | Detail |
|----------|--------|
| `attach_dids_to_dids` delegated | Closes the `rucio-it-tools` registration gap |
| `del_rule` / `update_rule` self-service | Rule owners can manage their own rules without privilege |
| `add_protocol` / `del_protocol` / `update_protocol` | Delegated with scheme allowlist (`davs`, `s3`, `https`, `root`, `xrdhttp`, `gsiftp`) |
| Data-driven bundle | RSE types and allowed schemes configurable at runtime — no redeploy |
| Admin bundle | `data.vo.admins[issuer]` fully wired alongside `is_admin` from Python |

**Rego policy path:** `vo/authz/v2/allow` (was `vo/authz/allow`)

**New `_PASSTHROUGH_KEYS`:** `scheme`, `hostname`, `attachments`, `rule_id`

## Actions delegated to OPA

| Category | Actions |
|----------|---------|
| Replication rules | `add_rule`, `del_rule`\*, `update_rule`\*, `approve_rule` |
| RSE management | `add_rse`, `update_rse`, `del_rse`, `add_rse_attribute`, `del_rse_attribute` |
| Protocol management | `add_protocol`\*, `del_protocol`\*, `update_protocol`\* |
| Data Identifiers | `add_did`, `add_dids`, `attach_dids`, `detach_dids`, `attach_dids_to_dids`\* |
| Everything else | → privileged-only fallback in Rego |

\* Phase 3 addition or behaviour change.

## Configuration

```ini
# rucio.cfg
[policy]
package = rucio_opa_v2_policy
```

| Variable | Default | Purpose |
|---|---|---|
| `OPA_URL` | `http://localhost:8181` | OPA server the policy module queries |
| `OPA_POLICY_PATH` | `vo/authz/v2/allow` | Rego rule path for this phase |
| `OPA_TIMEOUT` | `2` | Seconds before `query_opa()` fails closed |

Read by `opa_client.py` at request time — the compose file sets them per phase.
The policy bundle (`data.vo.policy`) is pushed separately at deploy time by
`scripts/ingest_policies.py`; Rego falls back to its hardcoded defaults when no
bundle is loaded.

## Running it

`make e2e PHASE=3` — see [Quick start](../../README.md#quick-start).

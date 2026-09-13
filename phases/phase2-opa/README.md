# rucio-opa-policy

Phase 2 — OPA as PDP, all authorisation logic in Rego.

## Actions delegated to OPA

| Category | Actions |
|----------|---------|
| Replication rules | `add_rule`, `del_rule`, `update_rule`, `approve_rule` |
| RSE management | `add_rse`, `update_rse`, `del_rse`, `add_rse_attribute`, `del_rse_attribute` |
| Data Identifiers | `add_did`, `add_dids`, `attach_dids`, `detach_dids` |
| Everything else | → privileged-only fallback in Rego |

## OPA input document

```json
{
  "issuer": "alice", "action": "add_rule",
  "is_root": false,  "is_admin": false,
  "kwargs": { "account": "alice", "locked": false,
              "rse_expression": "CERN_DATADISK" }
}
```

## Configuration

```ini
# rucio.cfg
[policy]
package = rucio_opa_policy
```

| Variable | Default | Purpose |
|---|---|---|
| `OPA_URL` | `http://localhost:8181` | OPA server the policy module queries |
| `OPA_POLICY_PATH` | `vo/authz/allow` | Rego rule path for this phase |
| `OPA_TIMEOUT` | `2` | Seconds before `query_opa()` fails closed |

Read by `opa_client.py` at request time — the compose file sets them per phase.

## Running it

`make e2e PHASE=2` — see [Quick start](../../README.md#quick-start).

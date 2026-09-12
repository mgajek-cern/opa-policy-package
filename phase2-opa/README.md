# rucio-opa-policy

Phase 2 — OPA as PDP, all authorisation logic in Rego.

---

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

---

## Install & configure

```bash
python3 -m pip install -e phase2-opa/
```

```bash
export RUCIO_POLICY_PACKAGE=rucio_opa_policy
export OPA_URL=http://localhost:8181       # default
export OPA_POLICY_PATH=vo/authz/allow     # default
export OPA_TIMEOUT=2
```

```ini
# rucio.cfg  [policy]
package = rucio_opa_policy
```

## Tests

```bash
# Start the full stack (Rucio + OPA + PostgreSQL) once for e2e + smoke
cd deploy/compose && docker compose -f docker-compose.phase2.yml up -d && cd ../..

# OPA — against OPA directly
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase2_opa.py -v

# Smoke — against Rucio's REST API
RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
    python3 -m pytest tests/test_phase2_rucio.py -v

# Teardown (add -v to also wipe the DB volume)
cd deploy/compose && docker compose -f docker-compose.phase2.yml down -v && cd ../..
```

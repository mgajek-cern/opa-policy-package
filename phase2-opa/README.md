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

| File | Covers |
|------|--------|
| `test_phase2_opa.py` | Unit — OPA client fail-closed, input construction (mocked, no live services) |
| `test_phase2_e2e.py` | Live OPA — RSE naming, account/DID ownership, privileged actions, update_rse |
| `test_phase2_smoke.py` | Live full stack — real Rucio REST API, auth, schema validation, and that Rucio actually calls OPA end-to-end |

```bash
# Unit tests — no services required
python3 -m pytest tests/test_phase2_opa.py -v

# Start the full stack (Rucio + OPA + PostgreSQL) once for e2e + smoke
cd phase2-opa/deploy && docker compose up -d && cd ../..

# E2E — against OPA directly
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase2_e2e.py -v

# Smoke — against Rucio's REST API
RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
    python3 -m pytest tests/test_phase2_smoke.py -v

# Teardown (add -v to also wipe the DB volume)
cd phase2-opa/deploy && docker compose down -v && cd ../..
```

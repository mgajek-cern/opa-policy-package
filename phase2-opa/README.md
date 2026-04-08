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
              "rse_expression": "CERN_DATADISK",
              "source_protocol": "webdav", "dst_protocol": "s3" }
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
python3 -m pytest tests/test_phase2_opa.py -v

# e2e (requires live OPA)
cd phase2-opa/docker && docker compose up -d opa opa-init && cd ../..
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase2_e2e_scenarios.py -v
cd phase2-opa/docker && docker compose down && cd ../..
```

| File | Covers |
|------|--------|
| `test_phase2_opa.py` | OPA client fail-closed, input construction |
| `test_phase2_e2e_scenarios.py` | Live OPA: protocol combos, RSE naming, DIDs, RSE attrs |

## Smoke Tests

```bash
cd phase2-opa/docker

# Full stack (OPA + PostgreSQL + Rucio)
docker compose --profile full up -d

# Run smoke tests against Rucio REST API
sleep 5
bash smoke_test.sh

# Teardown (add -v to also wipe the DB volume)
docker compose --profile full down -v

cd ../..
```

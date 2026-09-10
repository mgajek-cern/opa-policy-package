# rucio-opa-v2-policy

Phase 3 — OPA as PDP, data-driven configuration, broader action coverage. Policy bundle (`data.vo.policy`) is pushed at deploy time via `ingest_policies.py`. Rego falls back to hardcoded defaults when no bundle is loaded.

---

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

---

## Actions delegated to OPA

| Category | Actions |
|----------|---------|
| Replication rules | `add_rule`, `del_rule`\*, `update_rule`\*, `approve_rule` |
| RSE management | `add_rse`, `update_rse`, `del_rse`, `add_rse_attribute`, `del_rse_attribute` |
| Protocol management | `add_protocol`\*, `del_protocol`\*, `update_protocol`\* |
| Data Identifiers | `add_did`, `add_dids`, `attach_dids`, `detach_dids`, `attach_dids_to_dids`\* |
| Everything else | → privileged-only fallback in Rego |

\* Phase 3 addition or behaviour change.

---

## Install & configure

```bash
python3 -m pip install -e phase3-opa/
```

```bash
export RUCIO_POLICY_PACKAGE=rucio_opa_v2_policy
export OPA_URL=http://localhost:8181
export OPA_POLICY_PATH=vo/authz/v2/allow
export OPA_TIMEOUT=2
```

```ini
# rucio.cfg  [policy]
package = rucio_opa_v2_policy
```

## Tests

| File | Covers |
|------|--------|
| `test_phase3_opa.py` | Unit — OPA client fail-closed, new passthrough keys, `has_permission` propagation (mocked, no live services) |
| `test_phase3_e2e.py` | Live OPA — RSE naming, account/DID ownership, rule owner self-service, protocol scheme allowlist, data-driven bundle overrides |
| `test_phase3_smoke.py` | Live full stack — real Rucio REST API, auth, schema validation, and that Rucio actually calls OPA end-to-end |

```bash
# Unit tests — no services required
python3 -m pytest tests/test_phase3_opa.py -v

# Start the full stack (Rucio + OPA + PostgreSQL) once for e2e + smoke
cd phase3-opa/deploy && docker compose up -d && cd ../..

# E2E — against OPA directly
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase3_e2e.py -v

# Smoke — against Rucio's REST API
RUCIO_URL=http://localhost OPA_URL=http://localhost:8181 \
    python3 -m pytest tests/test_phase3_smoke.py -v

# Teardown (add -v to also wipe the DB volume)
cd phase3-opa/deploy && docker compose down -v && cd ../..
```

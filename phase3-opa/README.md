# rucio-opa-v2-policy

Phase 3 Rucio policy package — OPA as PDP, data-driven configuration, broader action coverage.

```
User request
    │
    ▼
Rucio server
    │
    ▼
has_permission()          Python — serialisation + is_admin resolution
    │
    │  POST /v1/data/vo/authz/v2/allow
    ▼
OPA server                Rego — policy + runtime data bundle
    │
    ├─ data.vo.policy             loaded by ingest_policies.py
    │     ├─ allowed_protocol_combos   (runtime-configurable)
    │     ├─ known_rse_types           (runtime-configurable)
    │     └─ allowed_schemes           (runtime-configurable)
    │
    ├─ data.vo.admins             {account: true, ...}
    │
    └─ authz.rego                 falls back to hardcoded defaults if no bundle
    │
    ▼
{ "result": true/false }
    │
    ▼
allow / deny              fail-closed: network error → deny
```

---

## What's new in Phase 3

| Addition | Detail |
|----------|--------|
| `attach_dids_to_dids` delegated | Closes the `rucio-it-tools` registration gap |
| `del_rule` / `update_rule` self-service | Rule owners can manage their own rules without privilege |
| `add_protocol` / `del_protocol` / `update_protocol` | Delegated with scheme allowlist (`davs`, `s3`, `https`, `root`, `xrdhttp`, `gsiftp`) |
| Data-driven bundle | Protocol combos, RSE types, allowed schemes configurable at runtime — no redeploy |
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

```bash
python3 -m pytest tests/test_phase3_opa.py -v

# e2e (requires live OPA)
cd phase3-opa/docker && docker compose up -d opa opa-init && cd ../..
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase3_e2e_scenarios.py -v
cd phase3-opa/docker && docker compose down
```

| File | Covers |
|------|--------|
| `test_phase3_opa.py` | OPA client fail-closed, new passthrough keys, `has_permission` propagation |
| `test_phase3_e2e_scenarios.py` | Live OPA |

## Smoke Tests

```bash
cd phase3-opa/docker

# Full stack (OPA + PostgreSQL + Rucio)
docker compose --profile full up -d

# Run smoke tests against Rucio REST API
sleep 5
bash smoke_test.sh

# Teardown (add -v to also wipe the DB volume)
docker compose --profile full down -v

cd ../..
```

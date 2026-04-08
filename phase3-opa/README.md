# rucio-opa-v2-policy

Phase 3 Rucio policy package — OPA as PDP, data-driven configuration,
broader action coverage.

Extends [Phase 2](../phase2-opa/README.md) with:

| Addition | Detail |
|----------|--------|
| `attach_dids_to_dids` delegated | Addresses the `rucio-it-tools` registration |
| `del_rule` / `update_rule` self-service | Rule owners can act on their own rules without privilege |
| `add_protocol` / `del_protocol` / `update_protocol` | Delegated with scheme allowlist enforcement |
| Data-driven policy bundle | Protocol combos, RSE types, and allowed schemes configurable at runtime via OPA data API — no redeploy needed |
| Admin set from bundle | `data.vo.admins[issuer]` fully wired — no longer requires `is_admin` from Python caller alone |

---

## What changes from Phase 2

**Rego policy path:** `vo/authz/v2/allow` (was `vo/authz/allow`)

**New `_PASSTHROUGH_KEYS` in `permission.py`:** `scheme`, `hostname`, `data`,
`attachments`, `rule_id` — required for the three new action groups.

**Data bundle** (`vo/policy`): operators push `allowed_protocol_combos`,
`known_rse_types`, and `allowed_schemes` via the OPA data API. The Rego
rules fall back to hardcoded defaults when no bundle is loaded, so the
package works in CI without a bundle server.

---

## Actions delegated to OPA

| Category | Actions |
|----------|---------|
| Replication rules | `add_rule`, `del_rule`\*, `update_rule`\*, `approve_rule` |
| RSE management | `add_rse`, `update_rse`, `del_rse`, `add_rse_attribute`, `del_rse_attribute` |
| Protocol management | `add_protocol`, `del_protocol`, `update_protocol` |
| Data Identifiers | `add_did`, `add_dids`, `attach_dids`, `detach_dids`, `attach_dids_to_dids`\* |
| Everything else | → privileged-only fallback in Rego |

\* Phase 3 addition or behaviour change.

### Self-service rule management

`del_rule` and `update_rule` now allow the rule's owning account to act on
their own rules. The Rucio API passes `kwargs["account"]` as the rule owner;
Rego checks `input.kwargs.account == input.issuer`. Privileged users retain
unrestricted access.

---

## OPA input document

Unchanged from Phase 2 — same shape, same Python serialisation layer.
New kwargs keys are transparently forwarded via the extended `_PASSTHROUGH_KEYS`.

---

## Start OPA only

```bash
cd phase3-opa/docker
docker compose up -d opa opa-init
```

## Start full stack (OPA + PostgreSQL + Rucio)

```bash
cd phase3-opa/docker
docker compose --profile full up -d
bash smoke_test.sh
```

## Ingest policies manually

```bash
cd phase3-opa/docker
python3 ingest_policies.py \
    --opa-url http://localhost:8181 \
    --admins alice,bob
```

## Configure

```bash
export RUCIO_POLICY_PACKAGE=rucio_opa_v2_policy
export OPA_URL=http://localhost:8181
export OPA_POLICY_PATH=vo/authz/v2/allow
export OPA_TIMEOUT=2
```

---

## Running the tests

```bash
python3 -m pip install pytest -e phase3-opa/

# Unit tests (OPA mocked)
python3 -m pytest tests/test_phase3_opa.py -v

# e2e tests (requires live OPA)
cd phase3-opa/docker && docker compose up -d opa opa-init && cd ../..
OPA_URL=http://localhost:8181 python3 -m pytest tests/test_phase3_e2e_scenarios.py -v
cd phase3-opa/docker && docker compose down
```

### Test structure

| File | What it covers |
|------|----------------|
| `test_phase3_opa.py` | OPA client fail-closed, new passthrough keys, `has_permission` propagation |
| `test_phase3_e2e_scenarios.py` | Live OPA: all inherited Phase 2 scenarios + Groups G/H/I/J |

### New scenario groups

| Group | Scenarios | What it validates |
|-------|-----------|-------------------|
| G | 5 | `attach_dids_to_dids` — scope owner, mock, other scope, admin |
| H | 8 | `del_rule` / `update_rule` owner self-service; `approve_rule` still privileged-only |
| I | 10 | Protocol scheme allowlist — allowed schemes, unknown schemes, case insensitivity |
| J | 4 | Data bundle overrides — custom RSE types, combo additions, scheme additions |

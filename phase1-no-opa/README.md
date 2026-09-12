# rucio-no-opa-policy

Phase 1 Rucio policy package — Rucio as PDP, permission logic inline in Python.

---

## What it enforces

**RSE naming** — `<SITE>_<TYPE>`, TYPE ∈ `{DATADISK, SCRATCHDISK, LOCALGROUPDISK, TAPE, USERDISK}`.

**Actions with custom logic:**

| Action | Extra check |
|--------|-------------|
| `add_rule` | RSE naming + account ownership |
| `add_rse` | Privileged + RSE naming |
| `update_rse` | Privileged + RSE naming on rename |

---

## Install & configure

```bash
python3 -m pip install -e phase1-no-opa/
```

```ini
# rucio.cfg
[policy]
package = rucio_no_opa_policy
```

## Tests

```bash
python3 -m pytest tests/test_phase1_rules.py tests/test_phase1_permission.py -v
```

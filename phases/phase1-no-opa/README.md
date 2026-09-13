# rucio-no-opa-policy

Phase 1 Rucio policy package — Rucio as PDP, permission logic inline in Python.

## What it enforces

**RSE naming** — `<SITE>_<TYPE>`, TYPE ∈ `{DATADISK, SCRATCHDISK, LOCALGROUPDISK, TAPE, USERDISK}`.

**Actions with custom logic:**

| Action | Extra check |
|--------|-------------|
| `add_rule` | RSE naming + account ownership |
| `add_rse` | Privileged + RSE naming |
| `update_rse` | Privileged + RSE naming on rename |

## Configuration

```ini
# rucio.cfg
[policy]
package = rucio_no_opa_policy
```

No external services and no environment variables — the decision is made in
Python, in-process.

## Running it

`make test PHASE=1` — see [Quick start](../../README.md#quick-start).

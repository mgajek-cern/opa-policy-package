# Policy Package Mechanism

## How Rucio loads a policy package

Rucio's permission system has a single extension point. When any API action
requires authorisation, the Rucio core calls exactly one function:

```python
has_permission(issuer, action, kwargs, session=session)
```

It never calls individual `perm_add_rule()` or `perm_del_rse()` functions
directly — those are internal implementation details of whichever module
provides `has_permission()`.

The module is resolved at startup via `rucio.cfg`:

```ini
[policy]
package = rucio_opa_policy   # or rucio_no_opa_policy for Phase 1
```

Rucio performs roughly:

```python
module = importlib.import_module(f"{package}.permission")
allowed = module.has_permission(issuer, action, kwargs, session=session)
```

Everything inside `has_permission()` is under the policy package's control.
The individual `perm_*` functions in Rucio's `generic.py` are a convention,
not a requirement imposed by the framework.

---

## Call sequence — Phase 1 (inline Python PDP)

```
User request (e.g. POST /rses/CERN_DATADISK)
    │
    ▼
Rucio REST API layer
    │  resolves action = "add_rse"
    ▼
rucio.core.permission.has_permission(issuer, "add_rse", kwargs)
    │  imports rucio_no_opa_policy.permission
    ▼
rucio_no_opa_policy.permission.has_permission()
    │  dispatch table: "add_rse" → perm_add_rse()
    ▼
perm_add_rse()
    ├── _is_root(issuer) or _is_admin(issuer)   [privilege check]
    └── is_rse_name_valid(kwargs["rse"])         [domain check — rules.py]
         │
         ▼
    True / False  ←──────────────────── returned to Rucio core
```

The policy logic lives entirely in Python. No external service is involved.
`rules.py` contains pure functions (protocol combos, RSE naming) that are
testable without any Rucio infrastructure.

---

## Call sequence — Phase 2 (OPA as external PDP)

```
User request (e.g. POST /rses/CERN_DATADISK)
    │
    ▼
Rucio REST API layer
    │  resolves action = "add_rse"
    ▼
rucio.core.permission.has_permission(issuer, "add_rse", kwargs)
    │  imports rucio_opa_policy.permission
    ▼
rucio_opa_policy.permission.has_permission()
    │
    ├── _build_input()
    │     ├── issuer.external          → "root"
    │     ├── is_root / is_admin       → resolved in Python (one DB call max)
    │     └── _serialisable_kwargs()   → strips Session, converts InternalAccount
    │
    └── query_opa(input_doc)           → opa_client.py
          │
          │  POST /v1/data/vo/authz/allow
          │  {
          │    "input": {
          │      "issuer":   "root",
          │      "action":   "add_rse",
          │      "is_root":  true,
          │      "is_admin": false,
          │      "kwargs":   { "rse": "CERN_DATADISK" }
          │    }
          │  }
          ▼
        OPA server
          │  evaluates authz.rego
          │
          │  _action_allowed if {
          │      input.action == "add_rse"
          │      _perm_add_rse          ← _is_privileged + _rse_name_valid()
          │  }
          ▼
        { "result": true }
          │
          ▼
    True / False  ←──────────────────── returned to Rucio core
```

OPA is the sole decision maker. The Python module is intentionally thin —
it only handles serialisation and the one DB call needed to resolve
`is_admin` (so Rego never needs a DB round-trip).

---

## Fail-closed behaviour

If OPA is unreachable for any reason (connection refused, timeout, malformed
response), `query_opa()` returns `False` and logs at `ERROR` level. The
request is denied. This is the correct default for a security boundary.

```
OPA unreachable
    │
    ▼
query_opa() catches URLError / TimeoutError
    │
    └── log.error("OPA unreachable — failing closed")
        return False   ← request denied
```

---

## What the policy package must provide

The only hard requirement imposed by Rucio is a `permission` module with
this exact signature:
```python
def has_permission(
    issuer: InternalAccount,
    action: str,
    kwargs: dict,
    *,
    session: Optional[Session] = None,
) -> bool:
    ...
```

The `action` strings (`"add_rse"`, `"add_rule"`, `"del_rse"`, etc.) are
**fixed identifiers defined by Rucio core** — they are hardcoded at the
call sites in `rucio/api/` and cannot be renamed by a policy package.
The kwargs dict structure is equally fixed: `kwargs["rse"]` for RSE actions,
`kwargs["account"]` and `kwargs["locked"]` for rules, and so on. The
package can only decide what to *do* with these values, not change what
they are called.

---

## Extending the Phase 2 policy

To delegate a new action to OPA:

1. **Rego** — add a rule to `authz.rego` and include the action name in
   the relevant action set (`_rule_actions`, `_rse_actions`, `_did_actions`,
   or a new set).

2. **Python** — add any new kwargs keys the Rego rule needs to
   `_PASSTHROUGH_KEYS` in `permission.py` so they survive serialisation.

3. **Tests** — add scenario tests to `test_phase2_e2e_scenarios.py` and a
   corresponding check to `smoke_test.sh`.

No changes to `has_permission()` itself are needed — it forwards everything
to OPA regardless of action.

# rucio-opa-policy

Rucio authorization policy package. Dispatches every `has_permission()`
call to one of two backends, selected by `AUTHZ_MODE`:

| `AUTHZ_MODE` | Path | Needs |
|---|---|---|
| `direct` (default) | Queries OPA directly | An OPA server (`OPA_URL`) with `policies/rego/phase6/authz.rego` loaded |
| `service` | Calls the Authorization Service over HTTP, via the generated `rucio_authz_client` | A running authz-service (`AUTHZ_SERVICE_URL`) — see [services/authorization-service](../../services/authorization-service/) |

Both modes decide against the same policy content and the same
entitlement/scope/rule-ownership model (design-003, design-004); only
the transport differs. See
[design-007](../../docs/design/design-007-fold-phase6-phase7-authz-mode.md)
for why these were folded into one package instead of two, and
[ADR-005](../../docs/adrs/adr-005-pdp-placement.md) for why `service`
mode exists at all.

## Installation

```bash
pip install -e phases/phase6-opa/
```

## Configuration

Common to both modes:

| Variable | Default | Notes |
|---|---|---|
| `AUTHZ_MODE` | `direct` | `direct` or `service` |
| `RUCIO_OPA_DEBUG_INPUT` | unset | `1`/`true` logs every outbound request at WARNING |

`AUTHZ_MODE=direct`:

| Variable | Default |
|---|---|
| `OPA_URL` | `http://localhost:8181` |
| `OPA_POLICY_PATH` | `vo/authz/v5/allow` |
| `OPA_TIMEOUT` | `2` |

`AUTHZ_MODE=service`:

| Variable | Default |
|---|---|
| `AUTHZ_SERVICE_URL` | `http://localhost:8000` |
| `AUTHZ_OIDC_AUDIENCE` | `authz-service` |
| `AUTHZ_REQUIRED_SCOPE` | `pep:rucio` |
| `AUTHZ_VO` | `def` |

`AUTHZ_MODE=service` additionally requires an existing OIDC subject
token on file for the calling account — x509/userpass/SSH/GSS accounts
get an explicit deny, not a silent fallback to `direct`.

## Test users

Seeded by `scripts/init-phase6.sh` (`AUTHZ_TEST_USERS`), all password
`secret` unless noted:

| Username | Password | Entitlement | Tier | Purpose |
|---|---|---|---|---|
| `adminuser` | `admin123` | `rucio-admins` | admin | privileged-path positive case |
| `randomaccount` | `secret` | `rucio-users` | user | privileged-path negative case; scope-ownership self-service |
| `depoperator` | `secret` | `dep-operator` | admin | DEP Operator persona (design-008) |
| `dependuser` | `secret` | `dep-end-user` | user | DEP End User persona (design-008) |
| `modeldeveloper` | `secret` | `model-developer` | user | Model Developer persona (design-008) |

The three DEP personas map onto the existing admin/user tiers with no new Rego branch — see [design-008](../../docs/design/design-008-dep-persona-entitlements.md).

## Layout

| Path | Holds |
|---|---|
| `src/rucio_opa_policy/permission.py` | `has_permission()`, dispatching on `AUTHZ_MODE` |
| `src/rucio_opa_policy/opa_client.py` | Thin synchronous OPA REST client, used by `direct` mode |
| `src/rucio_authz_client/` | Generated client for the Authorization Service, used by `service` mode (see [services/authorization-service/docs/python39-constraint.md](../../services/authorization-service/docs/python39-constraint.md) for why this generator) |

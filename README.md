# opa-policy-package

Rucio policy packages across six phases of increasing capability. Each phase is
a drop-in replacement — point Rucio at the package and restart; no data
migration required.

| Phase | Package | PDP | Summary |
|---|---|---|---|
| 1 | [`rucio-no-opa-policy`](phases/phase1-no-opa/README.md) | Rucio | RSE naming enforced in pure Python, no external dependencies. |
| 2 | [`rucio-opa-policy`](phases/phase2-opa/README.md) | OPA | Policy logic moves to OPA/Rego, delegating a wider set of actions. |
| 3 | [`rucio-opa-v2-policy`](phases/phase3-opa/README.md) | OPA | Data-driven configuration, self-service rule management, protocol scheme enforcement. |
| 4 | [`rucio-opa-v3-policy`](phases/phase4-opa/README.md) | OPA | `is_root`/`is_admin` DB lookup replaced by `wlcg.groups` from the token. |
| 5 | [`rucio-opa-v4-policy`](phases/phase5-opa/README.md) | OPA | WLCG group paths replaced by URN `entitlements`. |
| 6 | [`rucio-opa-v5-policy`](phases/phase6-opa/README.md) | OPA or authz-service | Same entitlement model, proven end to end against real TPC transfers through FTS. `AUTHZ_MODE` selects the transport: `direct` (default) queries OPA directly; `service` calls a standalone Authorization Service over HTTP, which queries the same policy — see [design-007](docs/design/design-007-fold-phase6-phase7-authz-mode.md). |

> See [Policy package mechanism](docs/policy-package-mechanism.md) for how Rucio
> loads a policy package, and [Action → Policy Mapping](docs/action-policy-mapping.md)
> for the full `has_permission()` coverage map — **required reading before
> writing Rego or ODRL policies.**

## Quick start

Every target takes `PHASE=1..6`; it defaults to 6. For Phase 6, `AUTHZ_MODE` selects the authorization transport and defaults to `direct`.

```bash
export PHASE=6

# Direct mode: Rucio queries OPA directly
export AUTHZ_MODE=direct
# Bring a phase up, initialise it, and run its suites
make e2e
```

or use the authz-service:

```bash
# Or use the authz-service
export AUTHZ_MODE=service
make e2e
```

The same Phase 6 compose stack is used for both modes. In `direct` mode, only the standard services are started. In `service` mode, the `authz-service` compose profile is enabled.

Step-by-step:

```bash
make install-dev   # test deps plus the selected phase package
make up            # compose up --wait
make init          # accounts, OIDC identities, RSEs, token exchange
make test          # whichever suites this phase has
make clean         # down -v
```

Phase 1 has no stack — `make test PHASE=1` runs standalone.

Phase 6 additionally runs transfers, which take several minutes. Both `AUTHZ_MODE` paths use the same compose file selection today — see [design-007](docs/design/design-007-fold-phase6-phase7-authz-mode.md) for what's collapsed and what (the compose files themselves) hasn't yet:

```bash
export PHASE=6
make e2e
make test-transfer
```

## Test suites

Each phase has some subset of these; a target for a suite the phase doesn't
have prints a line and exits clean.

| Suite | Boundary | Phases |
|---|---|---|
| `tests/test_phaseN_opa.py` | OPA directly, with handcrafted input documents | 2–6 |
| `tests/test_phaseN_rucio.py` | Rucio's REST API, with real tokens | 2–6 |
| `tests/test_phase6_full_transfer.py` | Rucio → FTS → storage, end to end | 6 |

Phase 6's suites run inside the `rucio-client` container, which has the certs and in-network DNS; the rest run on the host against `localhost`. The Makefile picks per phase, so the command is the same either way.

## Make targets

```bash
PHASE=6  package=phases/phase6-opa

  help             List targets
  install          pip install -e the selected phase's package
  install-dev      Install test dependencies plus the selected phase
  certs            Generate the CA and host certs
  up               Start the phase's stack and wait for healthchecks
  init             Register accounts, identities and (phase 6) RSEs and token exchange
  down             Stop the stack, keeping volumes
  clean            Stop the stack and wipe volumes
  ps               Show container status, including exited ones
  logs             Tail the stack's logs (SERVICE=rucio to narrow)
  dump             Print container status and recent logs (non-following; for CI)
  shell            Open a shell in a container (SERVICE=rucio)
  test-opa         Scenario tests against OPA directly
  test-rucio       Authorisation tests against Rucio's REST API
  test-transfer    End-to-end transfer tests (phase 6 only)
  test             Run every suite the phase has, except transfers
  lint             Run the pre-commit hooks over the whole tree
```

## Links

- [Rucio Policy Packages tutorial](https://indico.cern.ch/event/1545309/contributions/6742067/attachments/3167370/5629550/Policy%20Package%20Tutorial.pdf)
- [policy-package-template](https://github.com/rucio/policy-package-template)
- [opa-ri-scale reference implementation](https://github.com/federicaagostini/opa-ri-scale/tree/main)

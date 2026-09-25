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

Every target takes `PHASE=1..6`; it defaults to 6. Phase 6 additionally
takes `AUTHZ_MODE` — `direct` (default) or `service` — selecting whether
Rucio queries OPA directly or through the standalone Authorization
Service. Both modes run from the same compose file; `service` mode
additionally starts the `authz-service` container via a compose profile.

```bash
export PHASE=6
export AUTHZ_MODE=direct   # or: service

make e2e   # up, init, test
```

Step-by-step:

```bash
make install-dev   # test deps plus the selected phase package
make up             # compose up --wait
make init           # accounts, OIDC identities, RSEs, token exchange
make test           # whichever suites this phase/mode has
make clean          # down -v
```

Phase 1 has no stack — `make test PHASE=1` runs standalone.

Phase 6 also runs end-to-end transfers, which take several minutes and
today only run in `direct` mode:

```bash
export PHASE=6
export AUTHZ_MODE=direct
make e2e
make test-transfer
```

## Test suites

Each phase/mode has some subset of these; a target for a suite that
doesn't apply prints a line and exits clean.

| Suite | Boundary | Applies to |
|---|---|---|
| `tests/test_phaseN_opa.py` | OPA directly, with handcrafted input documents | phases 2–6 |
| `tests/test_phase6_rucio.py` | Rucio's REST API, real tokens, `AUTHZ_MODE=direct` | phase 6, direct |
| `tests/test_phase6_rucio_authz_service.py` | Rucio's REST API, real tokens, through authz-service | phase 6, service |
| `tests/test_phaseN_rucio.py` | Rucio's REST API, real tokens | phases 2–5 |
| `tests/test_phase6_full_transfer.py` | Rucio → FTS → storage, end to end | phase 6, direct only |

Phase 6's suites run inside the `rucio-client` container, which has the
certs and in-network DNS; earlier phases run on the host against
`localhost`. The Makefile picks the right suite for the current
`PHASE`/`AUTHZ_MODE` automatically.

## Make targets

```bash
PHASE=6  AUTHZ_MODE=direct  package=phases/phase6-opa

Overridable variables:
  PHASE=1..6          (default 6)
  AUTHZ_MODE=direct|service   phase 6 only (default direct)
  RUCIO_URL, OPA_URL, KEYCLOAK_URL   for a remote stack (non-container test runs)

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
  test-transfer    End-to-end transfer tests (phase 6, AUTHZ_MODE=direct only)
  test             Run every suite the phase has, except transfers
  lint             Run the pre-commit hooks over the whole tree
```

## Links

- [Rucio Policy Packages tutorial](https://indico.cern.ch/event/1545309/contributions/6742067/attachments/3167370/5629550/Policy%20Package%20Tutorial.pdf)
- [policy-package-template](https://github.com/rucio/policy-package-template)
- [opa-ri-scale reference implementation](https://github.com/federicaagostini/opa-ri-scale/tree/main)

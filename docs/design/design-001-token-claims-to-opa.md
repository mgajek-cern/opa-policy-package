# Design 001 — Getting token claims into the OPA input document

**Status:** implemented for phase 6 (2026-09-11). Option B. Phases 4 and 5
pending — same patches, `wlcg.groups` instead of `entitlements` for phase 4.

## Problem

`permission.py` (phases 4, 5, 6) builds the OPA input as:

    {
      "issuer": issuer.external,
      "action": action,
      "token": {"entitlements": _extract_entitlements(issuer)},
      "kwargs": _serialisable_kwargs(kwargs),
    }

and `_extract_entitlements()` does:

    token_info = getattr(issuer, "oidc_token_info", None) or {}
    return list(token_info.get("entitlements", []))

Rucio's policy-package contract is
`has_permission(issuer, action, kwargs, *, session)`, where `issuer` is an
`InternalAccount`: it carries `external` (the account name) and nothing
else. No Rucio code path attaches decoded JWT claims to it. The attribute
does not exist, `getattr` returns `None`, and `token.entitlements` is
always `[]`.

Consequence: `_is_privileged` is satisfied only by the bootstrap rule
`input.issuer == "root"`. Every entitlement- and group-driven rule in
rego/phase4, rego/phase5 and rego/phase6 is unreachable in a live stack.

## Why the tests didn't catch it

The coverage is real but the two halves never meet:

| Suite | Talks to | Proves |
|---|---|---|
| `test_phaseN_smoke.py::TestKeycloak*Claim` | Keycloak | the IdP mints the claim |
| `test_phaseN_smoke.py::TestRseManagement` | Rucio, as `root` via `/auth/userpass` | the OPA call is wired up |
| `test_phaseN_e2e.py` | OPA directly | the Rego evaluates claims correctly |

No test authenticates to Rucio with a token *and* asserts on a
claim-dependent decision.

## Options

### A. Look the token up in permission.py

`has_permission()` receives `session`. Query `models.Token` for the
account's newest unexpired row, decode the JWT, read the claim.

- No Rucio patch; works with the stock server.
- Costs a DB round-trip per authorisation decision, contradicting the
  phase 4/5 READMEs' "zero DB calls per decision".
- Ambiguous when an account has several valid tokens — this testbed already
  maps one OIDC identity to `root`, `ddmlab` and `randomaccount`, so
  "the account's token" is not well defined.

### B. Patch Rucio to carry the claims through

Attach the decoded token to the account object (or thread it through as a
kwarg) at the point where the request is authenticated, so
`has_permission()` receives it without a lookup.

- Matches what the Rego already expects; no per-decision DB cost.
- Another entry in `patches/rucio/`, which the repo already maintains for
  `oidc.py`, `rse.py`, `fts3.py` and `constants.py`.
- Needs a concrete insertion point — to be identified.

### C. Rethink the input contract

Have Rucio hand OPA the raw token and let the Rego (or an OPA
`http.send`/JWKS verifier) decode it. Largest change; parks the privilege
question in OPA entirely. Out of scope here, noted so it isn't lost.

**Recommendation:** B, falling back to A if no clean insertion point
exists. Decide after the verification step below.

**Decision: B.** A clean insertion point exists — see below. Option A's
DB round-trip and its ambiguity when one OIDC identity maps to several
accounts (this testbed maps one to `root`, `ddmlab` and `randomaccount`)
both argued against it. C remains open as a longer-term direction.

## Implementation

Claims were being decoded and discarded in two places, and the policy
module was reading them off an object that is rebuilt from a string long
before it reaches `has_permission()`. Five files, all small:

| File | Change |
|---|---|
| `rucio/core/authentication.py` | `_claims_from_jwt()`; `query_token()` attaches `claims` |
| `rucio/core/oidc.py` | `__get_rucio_jwt_dict()` carries `token_payload` as `claims` |
| `rucio/common/types.py` | `TokenValidationDict.claims: dict[str, Any]` |
| `rucio/web/rest/flaskapi/v1/common.py` | `request.environ['token_claims']` |
| `phase6-opa/.../permission.py` | `_extract_entitlements()` reads request scope |

The first four live in `patches/rucio/` and are mounted over site-packages
on both `rucio-server` and `rucio-daemons`.

Two paths reach `validate_auth_token`, and both needed covering:
`query_token()` for tokens already in the `tokens` table (anything
`init-testbed.sh` seeds, or that came through `/auth/oidc`), and
`validate_jwt()` → `__get_rucio_jwt_dict()` for a token presented to Rucio
for the first time. The testbed uses the former.

Carrying the whole payload rather than just `entitlements` means phase 4
(`wlcg.groups`) and phase 5 work from the same patch, and future claim
shapes need no further change.

`rucio.gateway.authentication.validate_auth_token` returns the core dict
unmodified, so the gateway needed no patch — verified, not assumed.

`_extract_entitlements()` wraps a bare string in a list: IdPs emit
single-valued claims as strings, and `list("urn:…")` would silently produce
a list of characters.

No daemon exposure: `grep has_permission lib/rucio/daemons/` is empty.
Daemons call core functions directly, so `has_permission()` is only ever
reached through a REST request and `request.environ` is always available.
The policy module still imports Flask defensively because unit tests
construct input documents outside a request context.

## Verification

With `RUCIO_OPA_DEBUG_INPUT=1` on `rucio-server`, presenting a seeded
Keycloak JWT for `ddmlab`:

    POST http://rucio-server/rses/OPAPROBE1
    X-Rucio-Auth-Token: eyJhbGciOiJSUzI1NiIs...

    OPA entitlements: claim_keys=['aud', 'azp', 'entitlements', 'exp',
      'iat', 'iss', 'jti', 'nbf', 'scope', 'session_state', 'sid', 'sub',
      'typ', 'wlcg.groups', 'wlcg.ver']
      entitlements=['urn:example:aai.example.org:group:atlas-users:role=member',
                    'urn:example:aai.example.org:group:rucio-users:role=member']
    OPA input for action=add_rse: {'issuer': 'ddmlab', 'action': 'add_rse',
      'token': {'entitlements': [...]}, 'kwargs': {...}}

Same request as `root` over userpass gives `claim_keys=[]`, which is
correct: a userpass token is not a JWT and has no claims to decode.

The 401 that follows is `AccessDenied: Account ddmlab can not add RSE` —
the OPA decision, not an auth failure. `add_rse` has no Rego rule, so it
falls through to `_is_privileged`.

## Remaining work

Tracked in BACKLOG.md, not blockers for this change:

1. **Action coverage.** `generic.py` has ~70 `perm_*` functions against the
   Rego's handful; everything unmatched falls through to `_is_privileged`.
   While the client authenticates as `root` this is invisible. It stops
   being invisible the moment the client switches to OIDC.
2. **Exercise it from the test suite.** `configs/rucio/phase6/
   oidc-client.cfg` mounted on `rucio-client` in place of
   `userpass-client.cfg`; `tests/conftest.py` needs a non-interactive
   `make_client()` (pre-writing the client token file is the likely route);
   `rego/phase6/authz.rego` needs `add_replicas` in `_all_known_actions`
   and a `_perm_did_action` scope check that tolerates `SCOPE = "ddmlab"`.
   Do (1) before this, or every smoke test fails at once for reasons
   unrelated to claims.
3. **Phases 4 and 5.** Same patches, mounted in the respective compose
   files. Phase 4 reads `wlcg.groups`, already present in the token.

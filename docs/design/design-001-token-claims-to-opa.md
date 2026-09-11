# Design 001 — Getting token claims into the OPA input document

**Status:** implemented for phase 6 (2026-09-11). Option B, with option D
documented as the fallback if patch maintenance becomes a burden. Phases 4
and 5 pending — same patches, `wlcg.groups` instead of `entitlements` for
phase 4.

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
  phase 4/5 READMEs' "no DB lookup in the decision path".
- Ambiguous when an account has several valid tokens, or when one identity
  maps to several accounts.

### B. Patch Rucio to carry the claims through

Decode the payload where the token is validated and thread it to request
scope, so `has_permission()` reads it without a lookup.

- Matches what the Rego already expects; no per-decision DB cost.
- Puts the claims on the path that already carries `issuer` and
  `identity` — the shape upstream would plausibly adopt.
- Four more entries in `patches/rucio/`, each a full file copy pinned to a
  Rucio version.

### C. Rethink the input contract

Hand OPA the raw token and let the Rego (or an OPA `http.send`/JWKS
verifier) decode it. Largest change; parks the privilege question in OPA
entirely. Out of scope here, noted so it isn't lost.

### D. Decode the header in permission.py

`has_permission()` runs inside a Flask request, after `request_auth_env`
has already validated the token. Read `X-Rucio-Auth-Token` off the request
and decode the payload in the policy module:

    def _extract_entitlements() -> list[str]:
        from flask import has_request_context, request
        if not has_request_context():
            return []
        token = request.headers.get("X-Rucio-Auth-Token", "")
        if len(token.split(".")) != 3:
            return []            # userpass/x509 — no claims
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        value = claims.get("entitlements", [])
        return [value] if isinstance(value, str) else list(value)

- Zero Rucio patches; survives every Rucio upgrade untouched.
- No DB call. Phases 4 and 5 need only their own `permission.py` changed.
- The safety argument is the same one option B relies on: the token in
  that header has already been validated by the `before_request` hook, so
  decoding without signature verification adds no trust the request does
  not already have.
- A policy package reaching into an HTTP header is a layering violation,
  and it breaks if Rucio ever accepts tokens somewhere other than that
  header.

**Decision: B**, with D as the documented fallback.

B is the more correct architecture and the one that could eventually be
upstreamed; D is the more robust one against Rucio churn. The deciding
factor was that the claims belong on the same path as `issuer` and
`identity`, not in a header read from a plugin. If patch maintenance
becomes a burden before an upstream equivalent exists, D is a
self-contained ~10-line change in a file this repo owns, with no other
moving parts.

A was ruled out on the DB round-trip and on identity ambiguity (this
testbed maps one OIDC identity to `root`, `ddmlab` and `randomaccount` —
see "Identity mapping" below). C remains open as a longer-term direction.

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
for the first time. The transfer tests use the former; the authz tests mint
a fresh token and exercise the latter.

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

## Maintaining the patches

Each patch is a full file copy, not a diff. On a Rucio upgrade they do not
conflict — they silently keep serving the old code, which is the failure
mode to design against.

The mitigation is to treat the Rucio version as pinned infrastructure
rather than a moving target:

- The compose files pin an image tag, and the patches are valid for exactly
  that tag. Upgrading Rucio is a deliberate step that includes re-deriving
  all of `patches/rucio/` from the new upstream files.
- For reproducibility beyond the upstream registry's retention, mirror the
  pinned image into an org-controlled registry namespace and reference that
  tag. This makes "which Rucio are these patches valid for" answerable from
  the compose file alone.
- Record the upstream Rucio version each patch was derived from in a header
  comment at the top of every file in `patches/rucio/`.

If this becomes untenable — or if an upstream change lands that makes the
claims available without patching — switch to option D, which removes all
four files.

Upstreaming `TokenValidationDict.claims` and the two lines that populate it
is worth attempting (the policy-package contract is exactly the case it
serves), but is not a dependency of this design: on realistic timescales
the pinned-image approach carries the testbed regardless.

## Identity mapping

`validate_jwt()` resolves the Rucio account from the token's
`SUB=…,ISS=…` identity. If one subject maps to several accounts, the
resolution is ambiguous — and because `root` is unconditionally privileged
under the bootstrap Rego rule, an ambiguous resolution can silently grant
privilege a test intended to deny.

`init-testbed.sh` therefore separates three roles:

| Keycloak user | Rucio account(s) | Purpose |
|---|---|---|
| `seeduser` | `root`, `ddmlab` | subject tokens for FTS exchange |
| `adminuser` | `adminuser` | authz test, `rucio-admins` entitlement |
| `randomaccount` | `randomaccount` | authz test, `rucio-users` only |

The seeding subject maps to two accounts by necessity — both need a
subject token and neither is used in the authz tests.
`assert_identities_unambiguous()` reports any subject mapped to more than
one account at the end of init, so a new one is visible rather than
mysterious.

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
the OPA decision, not an auth failure.

`tests/test_phase6_authz.py` makes this a regression test: `adminuser`
(`rucio-admins`) is allowed a privileged action, `randomaccount`
(`rucio-users`) is denied it with `ExceptionClass: AccessDenied`. The
positive case is the guard for the claims plumbing — the negative case
would pass with the patches reverted, since empty claims also deny.

## Remaining work

Tracked in BACKLOG.md, not blockers for this change:

1. **Rego action coverage (3a).** `add_replicas` and `add_dids` are
   addressed; `skip_availability_check` is deliberately left
   privileged-only, since Rucio treats it as an admin escalation and the
   client only requests it under `ignore_availability=True`. The remaining
   long tail of `perm_*` actions still falls through to `_is_privileged`,
   which stays invisible while the transfer suite runs as `root`.
2. **Move the transfer suite to OIDC (3b, later half).** The authz tests
   cover the claims path directly; switching `rucio-client` to
   `auth_type = oidc` additionally requires (1) to be complete, and a
   non-interactive `make_client()` — Rucio's OIDC client flow scrapes the
   IdP's HTML login form, so REST is used for the authz tests instead.
3. **Phases 4 and 5 (3c).** Same patches, mounted in the respective compose
   files. Phase 4 reads `wlcg.groups`, already present in the token.

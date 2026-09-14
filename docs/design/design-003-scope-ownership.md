# Design 003 — Resolving scope ownership against the DB

**Status:** implemented (2026-09-14)

## Problem

Every DID clause in rego/phase{4,5,6} decides ownership by string prefix:

    _perm_did_action if { startswith(input.kwargs.scope, input.issuer) }

Wrong in both directions:

- **Over-permissive.** Issuer `a` matches scope `alice.data`. Any account
  whose name is a prefix of another account's scope inherits write access to
  it. The Rego already carries a comment saying so.
- **Under-permissive.** An account that legitimately owns a scope not named
  after it — `ddmlab` owning `mock`, a group scope, anything created with
  `rucio-admin scope add --account X --scope Y` where the two differ — is
  denied.

Rucio's own `generic.py` does not guess. It calls

    rucio.core.scope.is_scope_owner(scope, account, session=session)

against the `scopes` table. That is the only authoritative answer, and no
token claim can substitute for it: the IdP has no concept of a Rucio scope.

Affected clauses, all phases: `add_did`, `attach_dids`, `detach_dids` (top-
level `kwargs.scope`), `add_dids` (every `did.scope`), `attach_dids_to_dids`
(every `attachments[_].scope`).

## Options

### A. Forward a boolean per request

Resolve in Python, send `kwargs.scope_owned: true`. Simplest, and for the
single-scope actions it is exactly right.

For the bulk actions it is not: `add_dids` carries a list, so a single
boolean means Python has already decided "all of them are owned". That moves
the decision out of OPA, which the phase 2 README explicitly positions as the
sole decision maker. The Rego's `every did in input.kwargs.dids` clause would
become decoration.

### B. Forward the set of scopes the issuer owns

Resolve the same lookups, but send the answers rather than the verdict:

    "kwargs": {
      "dids": [{"scope": "alice.a", ...}, {"scope": "alice.b", ...}],
      "owned_scopes": ["alice.a", "alice.b"]
    }

Rego keeps deciding:

    _perm_did_action if { input.kwargs.scope in input.kwargs.owned_scopes }

    _perm_did_action if {
        input.action == "add_dids"
        count(input.kwargs.dids) > 0
        every did in input.kwargs.dids {
            did.scope in input.kwargs.owned_scopes
        }
    }

Same number of DB lookups as A. The policy still expresses the rule; Python
only supplies a fact it is the only one able to fetch.

### C. Tighten the prefix to equality

`input.kwargs.scope == input.issuer`. Zero cost, removes the over-permissive
half, keeps the under-permissive half. Not a fix, but a strictly better
one-line state than today if (B) stalls.

**Decision: B**, with C as the fallback if the round-trip turns out to matter.

## Cost

The phase 4/5 READMEs claim "no Rucio DB round-trip per authorisation
decision". That claim was about resolving *privilege* — replacing the
`is_root`/`is_admin` lookups with a token claim — and it still holds: nothing
here touches `_is_privileged`. Ownership is a different question, and one the
token cannot answer.

Scope of the cost:

- Only DID actions. RSE, rule, protocol and replica actions are untouched.
- Deduplicate before querying: `add_dids` with 1000 DIDs usually spans one or
  two scopes, so it is one or two single-row lookups, not 1000.
- Rucio is about to hit the DB for the action itself regardless.

If it does become measurable, Rucio's `dogpile` regions are the obvious next
step — but not before there is a number.

## Implementation sketch

`permission.py`, all of phases 4/5/6 (phases 2/3 already resolve `is_admin`
in Python and can adopt the same helper):

    def _owned_scopes(issuer, kwargs, session) -> list[str]:
        scopes = _scopes_in(kwargs)          # kwargs.scope + did/attachment scopes
        return [s.external for s in scopes
                if is_scope_owner(scope=s, account=issuer, session=session)]

`has_permission()` already receives `session`; `_build_input()` gains it as an
argument. `_scopes_in()` needs the issuer as well as the kwargs, since building
an `InternalScope` from a bare string requires `issuer.vo`.

Serialisation is not free: the gateway converts scopes nested inside `dids[]`
and `attachments[]`, so `_serialisable_kwargs()`'s top-level-only `.external`
unwrap left objects `json.dumps` could not serialise, and every bulk DID action
failed closed before reaching OPA — including for root. `_externalise()`
recurses through dicts and lists instead.

## Testing

- `test_phase{4,5,6}_opa.py`: `owned_scopes` present and matching → allow;
  present and not matching → deny; the `add_dids` batch where one scope is
  absent from the set → deny. These are the cases the prefix check gets wrong,
  so they should fail against the current Rego.
- `test_phase{4,5,6}_rucio.py`: the existing self-service tests already cover
  the happy path end to end. Add one account owning a scope not named after
  it — the under-permissive case, which no current test can see.

## What this settles for the Authorization Service

adr-001's contract has a `resource` field and this repo has had nothing
principled to put in it: `kwargs.scope`, `kwargs.rse_expression`,
`kwargs.rse_id`, raw. opa-ri-scale models `resource` as a URI
(`resource.id`).

Deciding (B) fixes the shape of the answer before the contract is written: a
resource identifier plus the subject's relationship to it, resolved by
whoever can resolve it and evaluated by the PDP. Whether that relationship
travels as `owned_scopes` or as something more general is the contract's
problem — but it will not be "the policy re-derives ownership from a string".

## Non-goals

- Per-RSE/per-scope ABAC, rule expiry, maintenance windows. BACKLOG 4 step 2,
  still gated on the persona overview.
- `kwargs.account` for rules. `input.kwargs.account == input.issuer` compares
  two account names the gateway already resolved; it is exact and needs
  nothing.
- Caching. Named above as the escape hatch, not designed here.

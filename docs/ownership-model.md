# Ownership model in this policy package

Reference for the OPA authorisation path in phases 4/5/6. Covers only the
entities the Rego decides on — not the full schema.

**Scope of this document.** It describes how *this* package resolves and
evaluates ownership. Upstream Rucio's `lib/rucio/core/permission/generic.py`
still uses the older Python model: `perm_update_scope` calls
`is_scope_owner()`, rule updates are root-or-admin only, and
`perm_add_replicas` gates on RSE-name conventions rather than DID ownership.
Where the two differ, this document describes the package, not Rucio.

## The entities

| Table | Key | Ownership column | What it means |
|---|---|---|---|
| `accounts` | `account` | — | The principal. Everything below points here. |
| `account_map` | `identity`, `identity_type`, `account` | — | Maps an external identity to an account. |
| `scopes` | `scope` | `account` | Namespace owner. `is_scope_owner()` reads this. |
| `dids` | `scope`, `name` | `account` | The account recorded as owning this DID. |
| `rules` | `id` | `account` | Rule owner. Also carries `scope`/`name` — the data it acts on. |
| `replicas` | `scope`, `name`, `rse_id` | *(none)* | A physical copy; ownership is inherited from the DID. |
| `rses` | `id` | *(none, but `vo`)* | Storage endpoint. |

Three distinct `account` columns, answering three different questions:

- `scopes.account` — may this principal write into this namespace?
- `dids.account` — which account is recorded against this DID?
- `rules.account` — whose rule is this?

`dids.account` is a current authorisation fact, not immutable provenance.
Don't read it as "creator" in one place and "owner" in another.

`rules` couples two of them: one row names both an owner and a
`(scope, name)` subject. They can diverge — `update_rule` accepts an
`options.account` that reassigns the rule (`gateway/rule.py` converts it to
an `InternalAccount` before calling core, though upstream gates the whole
action on root/admin so no ordinary user reaches it), and a scope can be
reassigned after the rule exists. Any rule clause has to decide which of the
two it means.

`replicas` has no `account` column, and `_PASSTHROUGH_KEYS` forwards nothing
from an `add_replicas` request that identifies an owning account or DID —
only `rse` and `rse_id`. That is why `_perm_add_replicas` gates on privilege
level and RSE name rather than ownership.

## Where the token enters this path

Once, and before the policy module runs:

```
X-Rucio-Auth-Token
  → validate_auth_token()            core/authentication.py
  → validate_jwt() on first sight    core/oidc.py
  → identity string "SUB=…,ISS=…"
  → account_map lookup
  → account name
  → request.environ['issuer']
  → gateway/permission.py: InternalAccount(issuer, vo=vo)
  → has_permission(issuer, action, kwargs, session=…)
```

OPA therefore receives the *resolved Rucio account* as `input.issuer`. The
token determined which account that is; it does not travel further into the
ownership comparison. Note this describes the OIDC path into this package —
Rucio's permission layer can be reached by other credentials (userpass, x509)
and by callers that never touch this pipeline.

`assert_identities_unambiguous()` fails the testbed init rather than warning
because this package's OIDC contract requires an identity to resolve to
exactly one account. Ordinary Rucio permits one external identity to be
associated with several accounts; that is legitimate there and unusable here,
since the resolution would be non-deterministic. It also matters that one of
the candidates could be `root`, which this Rego short-circuits
unconditionally:

```rego
_is_privileged if { input.issuer == "root" }
```

## What the token decides, and what it doesn't

| Question | Answered by | Reaches OPA as |
|---|---|---|
| Who is this? | `account_map` | `input.issuer` |
| How privileged are they? | `entitlements` / `wlcg.groups` claim → bundle | `input.token.*` |
| How did they authenticate? | `acr` claim | `input.token.acr` |
| Do they own this scope? | `scopes` table | `input.kwargs.owned_scopes` |
| Do they own this rule? | `rules` table | `input.kwargs.rule_owner` / `rule_scope` (`del_rule`, `update_rule`) |

The split is the design:

> The token establishes the authenticated principal and supplies privilege
> claims; Rucio resolves resource ownership from its own state. By the time
> Rego evaluates a request, ownership comparisons are account-to-account
> rather than claim-to-resource.

The IdP has no authoritative knowledge of Rucio's current scope or rule
ownership — not because a claim couldn't assert it, but because Rucio has not
delegated that authority. It *has* delegated privilege, which is exactly what
`data.vo.entitlement_policy` does. Ownership stays with the database, which
is why `owned_scopes` is a list of retrieved facts rather than a boolean
verdict: Python supplies what only it can fetch, the Rego decides.

## Isolation between communities

Scope ownership is the finer grain *within* a VO. The fundamental tenancy
boundary in Rucio's model is the VO — `rses.vo`, and the VO prefix carried
inside every `InternalAccount` and `InternalScope`. That is namespace and
authorisation isolation; it is not physical or data-plane isolation, which
storage configuration decides.

A deployment holding, say, physics and clinical data in one VO gets little
separation from ownership checks alone: listing replicas and downloading by
PFN are not ownership-gated anywhere in this Rego.

## See also

- [design-003-scope-ownership.md](design/design-003-scope-ownership.md) — DID ownership, implemented.
- [design-004-rule-ownership.md](design/design-004-rule-ownership.md) — rule ownership, implemented.
- [policy-package-mechanism.md](policy-package-mechanism.md) — how Rucio loads `has_permission()`.

# Design-004: Ownership for rule actions

**Status:** implemented (2026-09-16) for phases 4, 5 and 6.

**Scope:** `add_rule`, `del_rule`, `update_rule`. Every other rule action
stays privileged-only — see "Actions deliberately left privileged" below.

## Problem

A rule row carries two distinct ownership facts, and the Rego currently
checks at most one of them — sometimes neither.

| Action | kwargs at permission time | What the Rego checks | Actual owner |
|---|---|---|---|
| `add_rule` | `dids`, `account`, `locked`, `rse_expression`, … | `account == issuer` | the requested rule owner ✓; the **data** is unchecked |
| `del_rule` | `rule_id`, `purge_replicas` | `kwargs.account == issuer` → **undefined** | `rules.account`, not in kwargs |
| `update_rule` | `rule_id`, `options` | `kwargs.account == issuer` → **undefined** | `rules.account`, not in kwargs |

Two problems follow:

1. **`del_rule` and `update_rule` advertise self-service and don't deliver
   it.** `input.kwargs.account` is never present for these actions, so the
   clause is undefined and both silently collapse to `_is_privileged`. Same
   class of failure as `add_dids` before design-003 gave it a clause.

2. **`add_rule` gates the rule, not the data.** `account == issuer` ensures
   the *requested* rule owner is the issuer. It says nothing about whether
   the issuer may replicate the DIDs named in `kwargs.dids`. In a
   single-tenant testbed that is unremarkable; in a deployment holding
   several communities' data in one VO, any account can create a rule
   pulling any other account's datasets onto storage it chooses.

Upstream is no guide here. `generic.py`'s `perm_del_rule` and
`perm_update_rule` are root-or-admin with no ownership path at all, so this
repo's self-service clause is its own policy choice — one made in the Rego
and never implemented.

### What ownership means for a rule

Two facts, both on the `rules` row, both reachable from one
`rucio.core.rule.get_rule(rule_id)`:

- **`rules.account`** — who owns the rule. The self-service question: "is
  this mine to change?"
- **`rules.scope` / `rules.name`** — the DID targeted by the rule. Its
  *scope* can then be checked against the issuer's owned scopes. The rule row
  does not itself establish data ownership; it names the resource whose
  ownership is then resolved the same way design-003 resolves any other
  scope.

They are independent and can diverge: an account may own a rule over data
whose scope has since been reassigned, or be handed a rule through
`update_rule`'s `options.account`.

## Decision

> **Security invariant.** A non-privileged principal may mutate a rule only
> when it owns that rule, and — for operations that can alter replication
> placement or lifetime — only when it also owns the scope the rule targets.
> Rule ownership and data ownership are independent facts, and neither
> implies the other.

Same shape as design-003: Python resolves facts, Rego decides.
`permission.py` forwards two new kwargs for rule-id-keyed actions:

    "kwargs": {
      "rule_id": "...",
      "rule_owner": "alice",
      "rule_scope": "alice.data"
    }

`rule_scope` then flows through the existing `_scopes_in()` collection, so
`owned_scopes` covers it without a second mechanism — the Rego asks
`input.kwargs.rule_scope in input.kwargs.owned_scopes` exactly as the DID
clauses do.

Which of the two facts each action requires is a policy question, answered
per action rather than uniformly:

| Action | Proposed rule | Why |
|---|---|---|
| `add_rule` | requested rule owner is issuer **and** every `dids[].scope` owned | Creating replication of data you don't own is the tenancy hole. |
| `del_rule` | rule owner is issuer | Deleting reduces access; requiring current data ownership would strand an account that can no longer clean up its own rules. |
| `update_rule` | rule owner is issuer **and** rule scope owned | Can extend lifetime and change RSE — an escalation in a way deletion is not. |
| `update_rule` requesting reassignment | privileged only | Handing a rule to another account is a transfer of ownership, not self-service. |

### Actions deliberately left privileged

The remaining rule actions keep the behaviour they have today. None of them
gains self-service here, and none regresses:

| Action | Today | After this design |
|---|---|---|
| `approve_rule` | `_is_privileged`, explicitly dispatched | unchanged — approval is the admin workflow by definition |
| `reduce_rule` | not in `_rule_actions` → catch-all → `_is_privileged` | unchanged |
| `move_rule` | not in `_rule_actions` → catch-all → `_is_privileged` | unchanged |
| `access_rule_vo` | not in `_rule_actions` → catch-all → `_is_privileged` | unchanged |

`reduce_rule` and `move_rule` are privileged-only by accident rather than by
decision, but privileged-only is the safe direction and they have no REST
route any current test suite exercises. When someone does need them: `reduce`
reduces copies, so it takes the `del_rule` argument (rule owner alone);
`move` places data on storage of the issuer's choosing, so it takes the
`update_rule` argument (owner **and** scope) and is the strongest case for
the data check of any rule action.

Do not simply add them to `_rule_actions` to "tidy up" — that set drives
`_is_known_action`, and adding `access_rule_vo` in particular would expose a
VO-boundary question this design does not answer.

## Implementation

`add_rule` — no Python change needed, `owned_scopes` is already forwarded
because `_SCOPE_CONTAINERS` includes `dids`:

```rego
_perm_add_rule if {
    _dst_rse_name_valid
    _src_rse_name_valid
    input.kwargs.account == input.issuer
    input.kwargs.locked == false
    count(input.kwargs.dids) > 0
    every did in input.kwargs.dids { did.scope in input.kwargs.owned_scopes }
}

_perm_add_rule if {
    _dst_rse_name_valid
    _src_rse_name_valid
    _is_privileged
}
```

`count(...) > 0` matters: on a request with no `dids`, `every` over an empty
collection is vacuously true, which would allow rather than deny. The
privileged clause is deliberately separate and unchanged — privilege
short-circuits ownership, as it does for DIDs.

The two rule-id-keyed actions:

```rego
_action_allowed if { input.action == "del_rule";    _perm_rule_owner }
_action_allowed if { input.action == "update_rule"; _perm_rule_owner_and_data }

_rule_reassignment_requested if {
    object.get(input.kwargs, ["options", "account"], null) != null
}

_perm_rule_owner if { _is_privileged }
_perm_rule_owner if { input.kwargs.rule_owner == input.issuer }

_perm_rule_owner_and_data if { _is_privileged }
_perm_rule_owner_and_data if {
    not _rule_reassignment_requested
    input.kwargs.rule_owner == input.issuer
    input.kwargs.rule_scope in input.kwargs.owned_scopes
}
```

`_rule_actions` itself does not change — `del_rule` and `update_rule` are
already members, and the dispatch lines above replace the single
`_perm_rule_owner_or_privileged` entry, which goes away.

The named predicate, rather than `not input.kwargs.options.account`, for two
reasons. `options` may be absent entirely, in which case the bare path
expression is undefined and `not` over it is vacuously true — correct here by
accident, but only by accident. And the truthiness form would also deny a
request that merely *names* the current owner, which is a no-op rather than a
transfer. `object.get` with a path and an explicit default makes both cases
explicit: reassignment is requested when the key is present and non-null,
regardless of its value.

### Python

**`options` must be added to `_PASSTHROUGH_KEYS`.** It is not there today, in
any phase, so `input.kwargs.options` never reaches OPA and the reassignment
check cannot fire as written. Without this the Rego above silently permits
reassignment by any rule owner.

```python
_RULE_ID_ACTIONS = frozenset({
    "del_rule", "update_rule",
})


def _rule_facts(action, kwargs, session):
    """{'rule_owner': ..., 'rule_scope': ...}, or {} when unresolvable."""
    if action not in _RULE_ID_ACTIONS or session is None:
        return {}
    rule_id = kwargs.get("rule_id")
    if not rule_id:
        return {}

    from rucio.common.exception import RuleNotFound
    from rucio.core.rule import get_rule

    try:
        row = get_rule(rule_id, session=session)
    except RuleNotFound:
        return {}
    except Exception:
        log.exception("OPA rule_facts: could not resolve rule %s", rule_id)
        return {}

    return {
        "rule_owner": row["account"].external,
        "rule_scope": row["scope"].external,
    }
```

Two failure modes, deliberately not collapsed. A missing rule is an ordinary
outcome: the keys are omitted, the Rego comparison is undefined, the action
denies. Anything else — a database error, a schema change, a bad id format —
is a fault, and the design decision is that **any inability to establish
ownership denies**, but never silently: it is logged at ERROR with a
traceback so the deny is traceable to its cause rather than looking like a
policy decision. A bare `except Exception: return {}` would make a transient
DB failure indistinguishable from "you don't own this rule" in the logs.

`_build_input()` merges the result into `serialisable` *before* computing `owned_scopes`, so `rule_scope` is picked up by `_scopes_in()` — which means `_scopes_in()` gains `rule_scope` alongside the `scope` key it already reads.

This is the first place `_build_input()` branches on the action. Worth
keeping the branch in one named helper rather than spreading action checks
through the module.

## Cost

One `get_rule()` per decision on two actions, `del_rule` and `update_rule`.
`add_rule` costs nothing new — `owned_scopes` already resolves its `dids`
scopes today, and this design is the first thing to read the result.

`del_rule` costs more than `update_rule`, and the reason is worth recording.
`gateway/rule.py:272` calls `has_permission` without `session=session`,
unlike every other call in that file. The gateway's `has_permission` is
`@read_session`-decorated, so a session is supplied — the policy module is
never handed `None`. But it is a *new read session*, not the enclosing
`db_session(WRITE)`, so there is no shared identity map with the
`delete_rule()` call that follows: two round-trips, and the read is not
guaranteed to see uncommitted state from the same request.

Not a blocker, and not a correctness problem for an ownership read. Worth
either passing the session through in a local patch or measuring before
deciding it doesn't matter.

## Testing

All three actions have REST routes the suites can already reach —
`POST /rules/`, `PUT /rules/<id>`, `DELETE /rules/<id>` — so no new client
plumbing is needed. `reduce` and `move` are separate POST subroutes nothing
currently exercises, which is part of why they stay out of scope.

- `test_phase{4,5,6}_opa.py`: `add_rule` with an unowned DID scope denied,
  with all scopes owned allowed, with an empty `dids` list denied; `del_rule`
  with matching and non-matching `rule_owner`; `update_rule` with owner
  matching but scope unowned denied; `options.account` present denied for a
  non-privileged issuer and allowed for a privileged one; `options` absent
  entirely still allowed for the owner.
- `test_phase{4,5,6}_rucio.py`: alice creates a rule over her own DID and
  deletes it; alice denied a rule over a DID in `aliceleak` (owned by
  adminuser, already seeded by the init scripts). No current Rucio suite
  deletes a rule, which is why the undefined clause went unnoticed — the
  integration test is what proves the session actually arrives.

## Non-goals

- `reduce_rule`, `move_rule`, `approve_rule`, `access_rule_vo`. All stay
  privileged-only; the first two are noted above with the argument each
  would take.
- Per-DID ownership via the `dids.account` column.
- Read-path gating (list replicas, download).
- Caching the `get_rule()` result. Revisit only with a number.

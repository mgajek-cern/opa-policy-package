# Design-NNN: [title]

**Status:** proposed (YYYY-MM-DD) | implemented (YYYY-MM-DD) [for <scope>].

**Implements:** ADR/design this fulfils, if any.

**Scope:** precise boundary, if not obvious from the title.

**Baseline:** what this builds on, if relevant.

## Problem / Premise / Summary

What's wrong, missing, or being proposed. Use a table if comparing
cases clarifies it. Pick whichever heading fits — a bug gets
"Problem", a new capability gets "Summary", a small consolidation
note gets "Premise".

## Options

Only if there was a real alternative worth recording. State the
decision inline ("Chosen: X, because...") or promote it to its own
Decision section below if the reasoning needs room to breathe.

## Decision

The chosen approach. State it as a rule where possible — the kind of
sentence every implementation choice below has to satisfy.

## Implementation

Named for what it actually is — Rego, Python, Architecture, whatever
the artifact is. The concrete part: code, contract fragments,
component layout. Note non-obvious choices in prose right after the
fragment they explain.

## Cost

Only if there's a real number or tradeoff worth recording — extra
round-trips, latency, an operational burden. Skip if there's nothing
to report.

## Testing

What proves this works, and why existing tests didn't already catch
the problem, if that's worth explaining.

## Non-goals

Only what's deliberately and permanently excluded, each with a
one-line reason. Skip the section entirely if there's nothing to
exclude — an empty Non-goals section is worse than no section.

## Open questions

Only if something genuinely unresolved remains for a future reader to
pick up. Omit rather than leave empty.

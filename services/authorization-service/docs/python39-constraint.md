# permission.py's client: openapi-generator python-legacy, not openapi-python-client

rucio-server (rucio/rucio-server:release-41.2.1) runs Python 3.9.25 —
AlmaLinux 9's default interpreter. EPEL9's `python3-gfal2` binding only
builds against that default; no 3.12-targeted build exists (confirmed
via `dnf list available` against AlmaLinux 9 with EPEL enabled). Moving
rucio-server off 3.9 means building gfal2's Python bindings from source
or changing base distro — out of scope here, tracked separately.

openapi-python-client's generated clients aren't 3.9-compatible, across
every version tried:
- 0.29.1 (current): generated setup.py pins python_requires>=3.11;
  client.py imports `Self` from `typing` (3.11+ only); model files use
  `A | B` union syntax at runtime (3.10+ only, since 0.28.3).
- 0.27.1 (pre-0.28.3, still lists 3.9 in its own classifiers): model
  files are fine, but client.py's own boilerplate (not schema-derived)
  still uses `X | None` runtime syntax — a different file hitting the
  same 3.10+ constraint.
- python-legacy (openapitools/openapi-generator, `-g python-legacy`,
  `compatibleWithPythonLegacy=true`, CLI pinned to v6.6.0 since the
  generator was later removed from mainline releases): generates real,
  honest Python 2/3-compatible typing (no `Self`, no `A | B`). Verified
  by importing all 47 generated modules under python:3.9-slim — clean.
  Needs one spec-level workaround: its regex-pattern postprocessor
  expects Perl-delimited `/pattern/` syntax, not bare regex — the
  Makefile's generate step rewrites `PrivilegedOperationRequest.
  operation`'s pattern before invoking the generator, on a throwaway
  copy of the spec, never the canonical openapi.yaml.

Conclusion: python-legacy is the one generator of those tried whose
output is reliably 3.9-safe. Its cost is real (older-style boilerplate,
a `six` dependency purely for legacy Py2 compatibility, and a pinned,
no-longer-actively-developed CLI version) but it works end to end,
confirmed against a live authz-service over the full rucio-server ->
has_permission() -> authz-service -> OPA chain.

Consequence: permission.py imports rucio_authz_client directly
(RulesApi, DidsApi, etc.) — synchronous by construction, since
python-legacy's client has no asyncio variant, so no event-loop
wrapping is needed. This is a *second*, independently-generated
rucio_authz_client from the *same* openapi.yaml — the python-legacy
one lives under phases/phase7-opa/src/ for rucio-server's Python 3.9;
authz-service's own clients/python (openapi-python-client, Python
3.12-only) is unrelated and unaffected by any of this.

Two model fields worth flagging for future editors, since they were
confirmed rather than assumed: `Subject.type`/`Subject.id` and
`DidAttachRequest.attachments` are all typed `object` by python-legacy
— it didn't generate an enum for Subject.type's OpenAPI `enum:` constraint,
and attachments is a generic passthrough rather than a typed nested
model list. Plain strings and plain dicts (with embedded model
instances inside them) both serialize correctly through ApiClient's
recursive `sanitize_for_serialization`, which is why permission.py's
builders use those shapes rather than dedicated wrapper classes.

# Licensed under the Apache License, Version 2.0
# Phase 2: OPA-delegating policy package (OPA is the PDP)
# has_permission() forwards every decision to a running OPA server
# via its REST API.  The Rego policies in ../rego/ encode the same
# rules as Phase 1 plus richer ABAC/ReBAC logic.

SUPPORTED_VERSION = [">=35.0.0"]

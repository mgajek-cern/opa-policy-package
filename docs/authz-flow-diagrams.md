# Authorization Flows via WP4 Authorization Service

Two consumer flows share the same integration pattern: caller obtains/holds a token appropriate to the regulatory context (GDPR, FDA, etc.) for audit purposes, then calls the WP4 Authorization Service through a client generated from its OpenAPI spec. The Authorization Service is the only component that talks to OPA.

## 1. Rucio → Authorization Service → OPA

```mermaid
sequenceDiagram
    actor Alice
    participant Rucio
    participant AuthZ as WP4 Authorization Service
    participant OPA as OPA (PDP)

    Alice->>Rucio: API request (user or service token,\nchosen per regulatory/audit context)
    Rucio->>AuthZ: POST /v1/authorize\n(generated OpenAPI client)
    AuthZ->>OPA: evaluate policy (Rego)
    OPA-->>AuthZ: allow / deny
    AuthZ-->>Rucio: decision { decision, reason }

    alt allowed
        Rucio->>Rucio: proceed (write rule, submit transfer, ...)
        Rucio-->>Alice: 201 Created
    else denied
        Rucio-->>Alice: 401/403
    end
```

Notes:
- Rucio never talks to OPA directly. It only knows the Authorization Service's OpenAPI contract.
- Token type (user vs. service token) is a Rucio-side concern driven by regulatory/audit requirements, not an Authorization Service concern — the service receives whatever subject/context the OpenAPI schema defines, regardless of which token backed it.

## 2. Storage endpoint → IAM (which hooks into the Authorization Service) → OPA

```mermaid
sequenceDiagram
    actor Client as User/Service (src or dst)
    participant SE as Storage Endpoint
    participant IAM as AAI IAM
    participant AuthZ as WP4 Authorization Service
    participant OPA as OPA (PDP)

    Client->>SE: push/pull request + token\n(src/dst, per regulatory/audit context)
    SE->>IAM: introspect(token)
    IAM->>IAM: validate token (issuer, expiry, audience)
    IAM->>AuthZ: POST /v1/authorize\n(generated OpenAPI client)
    AuthZ->>OPA: evaluate policy (Rego)
    OPA-->>AuthZ: allow / deny
    AuthZ-->>IAM: decision { decision, reason }
    IAM-->>SE: introspection result + decision

    alt allowed
        SE->>SE: accept transfer
    else denied
        SE-->>Client: reject
    end
```

Notes:
- The storage endpoint only ever calls IAM. IAM performs introspection and, within that same request handling, calls the Authorization Service on the storage endpoint's behalf — the SE does not call the Authorization Service directly.
- Token validation (issuer, expiry, audience) and the authorization decision remain two distinct operations against two distinct systems (IAM's own validation, then IAM's call out to the Authorization Service); they are logged as separate steps even though the storage endpoint sees them as a single response.
- This is a **new consumer relationship** not previously modeled in the action mapping: IAM acts as an authorization client for storage access flows, using the same Authorization Service contract as Rucio while supplying a token-centric authorization context.

## Shared architectural point for both flows

```mermaid
flowchart LR
    subgraph Direct callers
        R[Rucio]
        IAM[AAI IAM]
    end
    R -- OpenAPI client --> AZ[WP4 Authorization Service]
    IAM -- OpenAPI client, on behalf of SE --> AZ
    AZ --> OPA[OPA / Rego]
```

Rucio and IAM are the only direct callers of the Authorization Service. Storage endpoints reach it indirectly through IAM; FTS does not call it at all — its transfers are already authorized upstream by Rucio and re-checked downstream at the storage endpoint. Every direct caller generates its client from the same OpenAPI spec. OPA and Rego stay internal to the Authorization Service; no caller is coupled to Rego input shapes, which is the core reason a generated-client contract is viable here and isn't for Rego directly.

## Phase 6 — entitlement-driven authorisation

```mermaid
flowchart TD
    T["Request + X-Rucio-Auth-Token"] --> V["validate_auth_token<br/>claims → request.environ['token_claims']"]
    V --> P["permission.py builds the OPA input<br/>issuer, action, token.{entitlements, acr, aud, iss, sub}, kwargs"]
    P --> I{"issuer == 'root'?"}
    I -->|yes| PRIV["_is_privileged"]
    I -->|no| A{"data.vo.policy.required_acr set<br/>and token.acr matches?<br/>(absent → satisfied)"}
    A -->|no| U["not privileged"]
    A -->|yes| E{"entitlement mapped to 'admin'<br/>in data.vo.entitlement_policy?"}
    E -->|yes| PRIV
    E -->|no| L{"entitlement mapped to 'user'?"}
    L -->|yes| USER["user level"]
    L -->|no| U
    PRIV --> ALL["all actions, subject to<br/>RSE-name and scheme checks"]
    USER --> UADD["add_replicas on a<br/>name-valid RSE"]
    USER --> SELF
    U --> SELF["self-service clauses only"]
```

### What each action requires

```mermaid
flowchart LR
    subgraph ADMIN["privileged only"]
        A1["add_rse / update_rse<br/>del_rse / *_rse_attribute"]
        A2["approve_rule"]
        A3["add / del / update_protocol<br/>+ scheme allowlist"]
        A4["update_replicas_states<br/>delete_replicas"]
        A5["skip_availability_check<br/>+ every unlisted action"]
    end

    subgraph SELF["privileged OR ownership"]
        B1["add_rule<br/>account == issuer<br/>AND locked == false"]
        B2["del_rule / update_rule<br/>account == issuer"]
        B3["add_did / attach_dids /<br/>detach_dids<br/>scope in owned_scopes"]
        B4["add_dids<br/>every did.scope<br/>in owned_scopes"]
        B5["attach_dids_to_dids<br/>attachment scope<br/>in owned_scopes"]
    end

    subgraph LEVEL["privileged OR user level OR bundle opt-in"]
        C1["add_replicas<br/>entitlement → 'user'<br/>+ valid RSE name,<br/>or allow_replica_writes_to_<br/>allowlisted_rses"]
    end
```

| Action group | root | `rucio-admins` | `rucio-users` | no entitlement / userpass |
|---|---|---|---|---|
| RSE, protocol, approval, unlisted | ✓ | ✓ | ✗ | ✗ |
| `add_replicas` | ✓ | ✓ | valid RSE name | only with bundle flag |
| Rules | ✓ | ✓ | own account, unlocked, valid RSE | same |
| DIDs | ✓ | ✓ | own scope | same |

Verified by `tests/test_phase6_rucio.py`: `TestEntitlementAuthorisation`
covers the privileged path, `TestScopeOwnership` and `TestBulkScopeOwnership`
the ownership clauses against the scopes table, and `TestRuleSelfService` the
`kwargs.account` comparison. `tests/test_phase6_opa.py` covers the same rules
against synthetic input.

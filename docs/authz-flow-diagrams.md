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

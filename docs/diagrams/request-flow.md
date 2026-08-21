# Request flow

Every request that reaches a guarded route passes through the same choke point —
`requires(Action, ResourceRef)` — before the handler ever runs. The
diagnostics-error check (D6) is evaluated **before** the decision check, because an
`Allow` with errors is the dangerous case, not just a `Deny` with errors.

```mermaid
flowchart TD
    Start([HTTP request]) --> Auth{Authenticator chain}
    Auth -->|Bearer JWT valid| P1[JWT principal]
    Auth -->|X-API-Key valid| P2[API-key principal]
    Auth -->|no / invalid credentials| E401[401 Unauthorized]
    Auth -->|none presented| P3[Anonymous principal]

    P1 --> Req["requires(action, resource)"]
    P2 --> Req
    P3 --> Req

    Req --> Slice["EntityProvider.slice_for(principal, resource)"]
    Slice --> Vis{resource in slice?}
    Vis -->|no| E404["404 Not Found<br/>(not visible - a 403 would leak existence)"]
    Vis -->|yes| Engine[PolicyEngine.authorize]

    Engine --> D6{"diagnostics.errors non-empty? (D6)"}
    D6 -->|"yes - regardless of decision, including Allow"| E500[500 Internal Server Error]
    D6 -->|no| Dec{Decision}

    Dec -->|Deny| E403["403 Forbidden<br/>policy_id to audit log + app log only"]
    Dec -->|Allow| Handler[route handler]

    Handler --> Inv{domain invariant check}
    Inv -->|"violates e.g. LastSuperAdmin"| E409[409 Conflict]
    Inv -->|ok| Ok["2xx response"]
```

**Where each layer lives:** authentication (`app/auth/`) answers *who are you* and
exits at 401; authorization (`authz-core`, via `requires(...)`) answers *may you*
and exits at 403/404/500; domain invariants (`app/invariants/`, as Postgres
functions) answer *would the result be valid* and exit at 409. None of the three
imports another — see the README's Architecture section.

# ERD

The tables from `supabase/migrations/20260820000100_schema.sql`. `profiles` is the
only table that touches Supabase-owned identity (`auth.users`); everything else is
authorization and domain data owned by this service.

```mermaid
erDiagram
    organizations {
        uuid id PK
        text name
        timestamptz created_at
    }
    profiles {
        uuid id PK
        citext email
        text display_name
        timestamptz disabled_at
    }
    capabilities {
        text name PK
        text description
    }
    roles {
        uuid id PK
        uuid org_id FK
        text name
        role_scope scope
        text description
    }
    role_capabilities {
        uuid role_id FK
        text capability FK
    }
    org_memberships {
        uuid org_id FK
        uuid user_id FK
        uuid role_id FK
    }
    teams {
        uuid id PK
        uuid org_id FK
        text name
        boolean is_default
        uuid created_by FK
    }
    team_memberships {
        uuid team_id FK
        uuid user_id FK
        uuid role_id FK
    }
    workflows {
        uuid id PK
        uuid org_id FK
        uuid team_id FK
        text name
        jsonb definition
        uuid created_by FK
    }
    workflow_exports {
        uuid workflow_id PK
        boolean is_exported
        export_visibility visibility
        text password_hash
    }
    api_key_scopes {
        text name PK
        text description
    }
    api_keys {
        uuid id PK
        uuid user_id FK
        uuid org_id FK
        text prefix
        text key_hash
        timestamptz expires_at
        timestamptz revoked_at
    }
    api_key_grants {
        uuid api_key_id FK
        text scope FK
    }
    authz_audit_log {
        bigint id PK
        timestamptz at
        uuid org_id
        uuid principal_id
        text action
        text decision
        text policy_id
    }

    organizations ||--o{ org_memberships : has
    profiles ||--o{ org_memberships : holds
    roles ||--o{ org_memberships : grants
    organizations ||--o{ teams : has
    profiles ||--o{ teams : created_by
    teams ||--o{ team_memberships : has
    profiles ||--o{ team_memberships : holds
    roles ||--o{ team_memberships : grants
    roles ||--o{ role_capabilities : composed_of
    capabilities ||--o{ role_capabilities : referenced_by
    organizations ||--o{ roles : scopes
    organizations ||--o{ workflows : has
    teams ||--o{ workflows : has
    profiles ||--o{ workflows : created_by
    workflows ||--o| workflow_exports : has
    profiles ||--o{ api_keys : owns
    organizations ||--o{ api_keys : scoped_to
    api_keys ||--o{ api_key_grants : has
    api_key_scopes ||--o{ api_key_grants : referenced_by
    organizations ||--o{ authz_audit_log : logs
```

Notes not visible in the diagram itself:

- `profiles.id` references `auth.users(id) ON DELETE CASCADE` — populated by a
  trigger on `auth.users` insert, never a source of truth on its own.
- `roles.org_id IS NULL` marks a built-in role, shared by every tenant (partial
  unique index on `(name, scope)` for that case); non-null `org_id` scopes a
  custom role to exactly one org.
- `teams` has a partial unique index on `(org_id) WHERE is_default` — exactly one
  default team per org.
- `capabilities` and `api_key_scopes` are seed data, never user-writable.

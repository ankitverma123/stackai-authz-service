create extension if not exists citext;

create type role_scope as enum ('org', 'team');
create type export_visibility as enum ('public', 'org_only');

create table profiles (
    id           uuid primary key references auth.users(id) on delete cascade,
    email        citext not null,
    display_name text,
    disabled_at  timestamptz
);

create table organizations (
    id         uuid primary key default gen_random_uuid(),
    name       text not null,
    created_at timestamptz not null default now()
);

-- Seed data, never user-writable. A new row here requires a matching Cedar policy.
create table capabilities (
    name        text primary key,
    description text not null
);

create table roles (
    id          uuid primary key default gen_random_uuid(),
    org_id      uuid references organizations(id) on delete cascade,
    name        text not null,
    scope       role_scope not null,
    description text,
    unique (org_id, name, scope)
);
-- Built-ins (org_id is null) must be globally unique by name+scope.
create unique index roles_builtin_unique on roles (name, scope) where org_id is null;

create table role_capabilities (
    role_id    uuid not null references roles(id) on delete cascade,
    capability text not null references capabilities(name),
    primary key (role_id, capability)
);

create table org_memberships (
    org_id  uuid not null references organizations(id) on delete cascade,
    user_id uuid not null references profiles(id) on delete cascade,
    role_id uuid not null references roles(id),
    primary key (org_id, user_id)
);

create table teams (
    id         uuid primary key default gen_random_uuid(),
    org_id     uuid not null references organizations(id) on delete cascade,
    name       text not null,
    is_default boolean not null default false,
    -- Needed by the team_creator_is_admin trigger. Null for the default team,
    -- which is created alongside the org rather than by a user.
    created_by uuid references profiles(id),
    created_at timestamptz not null default now(),
    unique (org_id, name)
);
create unique index teams_one_default_per_org on teams (org_id) where is_default;

create table team_memberships (
    team_id uuid not null references teams(id) on delete cascade,
    user_id uuid not null references profiles(id) on delete cascade,
    role_id uuid not null references roles(id),
    primary key (team_id, user_id)
);

create table workflows (
    id         uuid primary key default gen_random_uuid(),
    org_id     uuid not null references organizations(id) on delete cascade,
    team_id    uuid not null references teams(id) on delete cascade,
    name       text not null,
    definition jsonb not null default '{}'::jsonb,
    created_by uuid references profiles(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index workflows_team_idx on workflows (team_id);
create index workflows_org_idx on workflows (org_id);

create table workflow_exports (
    workflow_id   uuid primary key references workflows(id) on delete cascade,
    is_exported   boolean not null default false,
    visibility    export_visibility not null default 'public',
    password_hash text,
    created_at    timestamptz not null default now()
);

create table api_key_scopes (
    name        text primary key,
    description text not null
);

create table api_keys (
    id           uuid primary key default gen_random_uuid(),
    user_id      uuid not null references profiles(id) on delete cascade,
    org_id       uuid not null references organizations(id) on delete cascade,
    name         text not null,
    prefix       text not null unique,
    key_hash     text not null,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz not null default now()
);

create table api_key_grants (
    api_key_id uuid not null references api_keys(id) on delete cascade,
    scope      text not null references api_key_scopes(name),
    primary key (api_key_id, scope)
);

create table authz_audit_log (
    id             bigserial primary key,
    at             timestamptz not null default now(),
    org_id         uuid,
    principal_id   uuid,
    auth_method    text,
    action         text not null,
    resource_type  text,
    resource_id    uuid,
    decision       text not null,
    policy_id      text,
    correlation_id uuid
);
create index authz_audit_org_at_idx on authz_audit_log (org_id, at desc);

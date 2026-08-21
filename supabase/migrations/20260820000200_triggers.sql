-- Mirror auth.users into profiles so we can join without cross-schema pain.
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    insert into profiles (id, email, display_name)
    values (new.id, new.email, coalesce(new.raw_user_meta_data ->> 'display_name', new.email))
    on conflict (id) do nothing;
    return new;
end; $$;

create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function handle_new_user();

-- A membership's role must match its scope AND belong to the same org (or be built-in).
create or replace function check_org_membership_role() returns trigger
language plpgsql as $$
declare r roles%rowtype;
begin
    select * into r from roles where id = new.role_id;
    if r.scope <> 'org' then
        raise exception 'role % is not org-scoped', r.name;
    end if;
    if r.org_id is not null and r.org_id <> new.org_id then
        raise exception 'role % belongs to another organization', r.name;
    end if;
    return new;
end; $$;

create trigger org_membership_role_check
    before insert or update on org_memberships
    for each row execute function check_org_membership_role();

create or replace function check_team_membership_role() returns trigger
language plpgsql as $$
declare r roles%rowtype; team_org uuid;
begin
    select * into r from roles where id = new.role_id;
    select org_id into team_org from teams where id = new.team_id;
    if r.scope <> 'team' then
        raise exception 'role % is not team-scoped', r.name;
    end if;
    if r.org_id is not null and r.org_id <> team_org then
        raise exception 'role % belongs to another organization', r.name;
    end if;
    return new;
end; $$;

create trigger team_membership_role_check
    before insert or update on team_memberships
    for each row execute function check_team_membership_role();

-- Every org member automatically joins the org's default team as a viewer.
-- This is how "org-level shared resources" work with no special case in the policy layer.
create or replace function join_default_team() returns trigger
language plpgsql as $$
declare dt uuid; viewer uuid;
begin
    select id into dt from teams where org_id = new.org_id and is_default;
    select id into viewer from roles where name = 'viewer' and scope = 'team' and org_id is null;
    if dt is not null then
        insert into team_memberships (team_id, user_id, role_id)
        values (dt, new.user_id, viewer)
        on conflict (team_id, user_id) do nothing;
    end if;
    return new;
end; $$;

create trigger org_member_joins_default_team
    after insert on org_memberships
    for each row execute function join_default_team();

-- A team's creator is its admin. This is an atomic SIDE EFFECT, not a counting
-- invariant: no aggregation, nothing to race on. It belongs here with the
-- constraints rather than in the §8 RPC functions. Without it a user can create
-- a team they have no capability to administer.
create or replace function team_creator_is_admin() returns trigger
language plpgsql as $$
declare admin_role uuid;
begin
    if new.created_by is null then
        return new;   -- default team, created with the org
    end if;
    select id into admin_role
    from roles where name = 'admin' and scope = 'team' and org_id is null;

    insert into team_memberships (team_id, user_id, role_id)
    values (new.id, new.created_by, admin_role)
    on conflict (team_id, user_id) do update set role_id = excluded.role_id;
    return new;
end; $$;

create trigger team_creator_is_admin
    after insert on teams
    for each row execute function team_creator_is_admin();

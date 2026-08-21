-- Counting invariants. These live here rather than in Python because PostgREST
-- gives every request its own transaction: a count and a delete issued from the
-- client are two transactions with a race between them. Inside one function they
-- are one transaction, and a per-org advisory lock serialises concurrent callers.

create or replace function remove_org_member(p_org_id uuid, p_user_id uuid)
returns void language plpgsql as $$
declare remaining int;
begin
    -- Advisory lock, NOT `for update`: PostgreSQL rejects row-locking clauses
    -- combined with aggregates ("FOR UPDATE is not allowed with aggregate
    -- functions" — verified), and row locks would deadlock here anyway, since
    -- two concurrent removals each lock the row the other deletes. Serialising
    -- per-org makes the second caller wait and re-count. Released at commit.
    perform pg_advisory_xact_lock(hashtextextended(p_org_id::text, 0));

    select count(*) into remaining
    from org_memberships m
    join role_capabilities rc on rc.role_id = m.role_id
    where m.org_id = p_org_id
      and rc.capability = 'manage_org'
      and m.user_id <> p_user_id;

    if remaining = 0 then
        raise exception using errcode = 'ZA001',
            message = 'Cannot remove the last super-admin: the organization would '
                      'become permanently unmanageable.';
    end if;

    -- Assumption #2: removal from an org cascades out of that org's teams.
    -- NOT an FK cascade (team_memberships cascades on profiles, not on org
    -- membership), so it must be explicit or the documented behaviour never
    -- happens. Safe under the org lock: every team mutation in this org takes
    -- that same lock first.
    delete from team_memberships tm
    using teams t
    where tm.team_id = t.id and t.org_id = p_org_id and tm.user_id = p_user_id;

    delete from org_memberships where org_id = p_org_id and user_id = p_user_id;
end; $$;

create or replace function change_org_role(p_org_id uuid, p_user_id uuid, p_role_id uuid)
returns void language plpgsql as $$
declare remaining int; keeps_manage_org boolean;
begin
    select exists (
        select 1 from role_capabilities
        where role_id = p_role_id and capability = 'manage_org'
    ) into keeps_manage_org;

    if not keeps_manage_org then
        perform pg_advisory_xact_lock(hashtextextended(p_org_id::text, 0));

        select count(*) into remaining
        from org_memberships m
        join role_capabilities rc on rc.role_id = m.role_id
        where m.org_id = p_org_id and rc.capability = 'manage_org'
          and m.user_id <> p_user_id;

        if remaining = 0 then
            raise exception using errcode = 'ZA001',
                message = 'Cannot demote the last super-admin: the organization would '
                          'become permanently unmanageable.';
        end if;
    end if;

    update org_memberships set role_id = p_role_id
    where org_id = p_org_id and user_id = p_user_id;
end; $$;

create or replace function remove_team_member(
    p_team_id uuid, p_user_id uuid, p_actor_is_super_admin boolean
) returns void language plpgsql as $$
declare remaining int; is_default_team boolean; v_org_id uuid;
begin
    select org_id, is_default into v_org_id, is_default_team
    from teams where id = p_team_id;

    -- LOCK DISCIPLINE: org first, then team. Two different advisory keys give no
    -- mutual exclusion even though the row sets overlap: remove_org_member's
    -- cascade writes team_memberships while holding only the org key, so a
    -- concurrent team removal would count a member the cascade is about to
    -- delete and strand the team with no admin. Consistent ordering also makes
    -- deadlock between two both-lock functions impossible.
    perform pg_advisory_xact_lock(hashtextextended(v_org_id::text, 0));
    perform pg_advisory_xact_lock(hashtextextended(p_team_id::text, 0));

    if is_default_team then
        raise exception using errcode = 'ZA003',
            message = 'Members cannot leave the default team while they belong to '
                      'the organization.';
    end if;

    if not p_actor_is_super_admin then
        select count(*) into remaining
        from team_memberships m
        join role_capabilities rc on rc.role_id = m.role_id
        where m.team_id = p_team_id and rc.capability = 'manage_members'
          and m.user_id <> p_user_id;

        if remaining = 0 then
            raise exception using errcode = 'ZA002',
                message = 'Cannot remove the last team admin. An organization '
                          'super-admin can perform this action.';
        end if;
    end if;

    delete from team_memberships where team_id = p_team_id and user_id = p_user_id;
end; $$;

create or replace function change_team_role(
    p_team_id uuid, p_user_id uuid, p_role_id uuid, p_actor_is_super_admin boolean
) returns void language plpgsql as $$
declare remaining int; v_org_id uuid; keeps_manage_members boolean;
begin
    select org_id into v_org_id from teams where id = p_team_id;
    perform pg_advisory_xact_lock(hashtextextended(v_org_id::text, 0));
    perform pg_advisory_xact_lock(hashtextextended(p_team_id::text, 0));

    -- Demotion is the other way to strand a team. remove_team_member covers
    -- removal; without this, PATCH .../members/{user} could demote the last admin
    -- to viewer with no check at all. Mirrors change_org_role's conditional shape.
    select exists (
        select 1 from role_capabilities
        where role_id = p_role_id and capability = 'manage_members'
    ) into keeps_manage_members;

    if not keeps_manage_members and not p_actor_is_super_admin then
        select count(*) into remaining
        from team_memberships m
        join role_capabilities rc on rc.role_id = m.role_id
        where m.team_id = p_team_id and rc.capability = 'manage_members'
          and m.user_id <> p_user_id;

        if remaining = 0 then
            raise exception using errcode = 'ZA002',
                message = 'Cannot demote the last team admin. An organization '
                          'super-admin can perform this action.';
        end if;
    end if;

    update team_memberships set role_id = p_role_id
    where team_id = p_team_id and user_id = p_user_id;
end; $$;

create or replace function delete_team(p_team_id uuid)
returns void language plpgsql as $$
declare is_default_team boolean; v_org_id uuid;
begin
    select org_id, is_default into v_org_id, is_default_team
    from teams where id = p_team_id;

    -- Same discipline: org lock first, then team (deleting a team removes its
    -- team_memberships rows).
    perform pg_advisory_xact_lock(hashtextextended(v_org_id::text, 0));
    perform pg_advisory_xact_lock(hashtextextended(p_team_id::text, 0));

    if is_default_team then
        raise exception using errcode = 'ZA003',
            message = 'The default team holds organization-level shared resources '
                      'and cannot be deleted.';
    end if;
    delete from teams where id = p_team_id;
end; $$;

create or replace function delete_role(p_role_id uuid)
returns void language plpgsql as $$
declare in_use int;
begin
    -- Matches the spec's ZA004 lock-scope row. Strictly, the FK share lock a
    -- concurrent membership insert takes on `roles` already serialises this, but
    -- spec and implementation must not disagree about something this subtle.
    perform pg_advisory_xact_lock(hashtextextended(p_role_id::text, 0));

    select (select count(*) from org_memberships where role_id = p_role_id)
         + (select count(*) from team_memberships where role_id = p_role_id)
      into in_use;

    if in_use > 0 then
        raise exception using errcode = 'ZA004',
            message = 'This role is still assigned to members and cannot be deleted.';
    end if;

    -- Built-ins are not deletable. Filtering them out in the WHERE clause instead
    -- would match zero rows and return normally, so DELETE /v1/roles/{builtin}
    -- would answer 204 having deleted nothing.
    if not exists (select 1 from roles where id = p_role_id and org_id is not null) then
        raise exception using errcode = 'ZA004',
            message = 'Built-in roles cannot be deleted.';
    end if;

    delete from roles where id = p_role_id;
end; $$;

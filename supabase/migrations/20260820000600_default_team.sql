-- The assignment's default team: "By default all org members belong to a special
-- team that contains resources shared at the organization level." The
-- join_default_team trigger already enrolls each new org member into the org's
-- team where is_default = true — but nothing created that team, because org
-- creation is done manually (no create-org endpoint is in scope). This trigger
-- closes the loop: every organization gets its default team the moment it is
-- created, so the "shared org-level team" behaviour is automatic for any org,
-- however it was inserted (seed, SQL, or a future endpoint).
--
-- created_by is null so team_creator_is_admin skips it (a default team has no
-- human creator); the partial unique index teams_one_default_per_org guarantees
-- at most one per org.
create or replace function create_default_team() returns trigger
language plpgsql as $$
begin
    insert into teams (org_id, name, is_default, created_by)
    values (new.id, 'General', true, null)
    on conflict do nothing;
    return new;
end; $$;

create trigger org_gets_default_team
    after insert on organizations
    for each row execute function create_default_team();

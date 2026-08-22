-- Grant the PostgREST connection role (service_role) access to the application
-- tables. All data access goes through supabase-py as service_role, which bypasses
-- RLS by design (spec §11 / README's enforcement model) -- so no RLS policies are
-- written and these table grants are the only thing that lets the app read/write.
--
-- Without them every query fails with "permission denied for table ..." (SQLSTATE
-- 42501). Hosted Supabase happens to provision service_role via default privileges
-- during initial role setup; encoding the grants here makes the schema
-- self-contained, so a fresh database (local `supabase db reset`, CI, or a new
-- project) works without any manual GRANTs.
--
-- Runs last (0500 > 0400) so `grant ... on all tables` covers everything created by
-- the earlier migrations; the ALTER DEFAULT PRIVILEGES lines cover any tables added
-- afterwards.
grant usage on schema public to service_role;
grant all on all tables in schema public to service_role;
grant all on all sequences in schema public to service_role;

alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public grant all on sequences to service_role;

# StackAI Authorization Service

Multi-tenant authentication and authorization for a workflow platform with an
Organization → Team → User hierarchy, plus unauthenticated access to published workflows.
Authorization decisions are made by [Cedar](https://www.cedarpolicy.com/) (`cedarpy`), through a
policy engine packaged separately from the HTTP service so it is reusable outside a web request.

## Quickstart

```bash
cp .env.example .env                    # fill SUPABASE_* from `supabase status -o env` after starting it
supabase start                          # local Postgres + GoTrue + PostgREST (not in docker-compose)
supabase db reset                        # applies supabase/migrations/* — schema, triggers, seed data, service_role grants
docker compose up -d --build
curl -fsS localhost:8000/health         # {"status": "ok"}
```

Supabase signs user access tokens with **ES256** (asymmetric), so `.env`'s `SUPABASE_JWKS_URL` must
point at `${SUPABASE_URL}/auth/v1/.well-known/jwks.json` (preset in `.env.example`) or real tokens
will not verify. `supabase db push` also applies the `service_role` table grants
(`20260820000500_service_role_grants.sql`); without them every query fails with `permission denied`.

`docker compose up` runs the API container only — local Supabase is a separate process started by
the Supabase CLI (`supabase start`), which is how `supabase/config.toml` and the migrations are
meant to be driven. `supabase/migrations/20260820000300_seed.sql` seeds `capabilities`,
`api_key_scopes`, and the five built-in roles (`member`, `super_admin`, `viewer`, `editor`,
`admin`); it does **not** seed any user accounts, organizations, or memberships — there are no
demo login credentials. Create a user through Supabase Auth and bootstrap their first
organization membership directly:

```bash
curl -s "$SUPABASE_URL/auth/v1/signup" -H "apikey: $SUPABASE_SERVICE_ROLE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"correct-horse-battery"}'   # signup auto-creates the profiles row
# then, against the local Postgres:
#   insert into organizations (id, name) values ('...', 'Demo Org');
#   insert into org_memberships (org_id, user_id, role_id)
#     values ('...', '<the new user id>', '00000000-0000-0000-0000-000000000002'); -- super_admin
# get a token for requests (grant_type=password returns an ES256 access_token):
#   curl "$SUPABASE_URL/auth/v1/token?grant_type=password" -H "apikey: $SUPABASE_SERVICE_ROLE_KEY" \
#     -H "Content-Type: application/json" -d '{"email":"demo@example.com","password":"correct-horse-battery"}'
```

For the non-HTTP reusability proof (dev/demo only — not shipped in the production image):

```bash
uv run authz check --role editor --action WorkflowUpdate   # ALLOW, cap-edit
uv run authz check --role viewer --action WorkflowUpdate   # DENY
```

## Architecture

Three layers, none importing another — see [`docs/diagrams/request-flow.md`](docs/diagrams/request-flow.md):

- **Authentication** (`src/app/auth/`) — *who are you?* Bearer JWT → `X-API-Key` → Anonymous
  chain. Exits at 401.
- **Authorization** (`packages/authz-core/`) — *may you?* A pip-installable package with **zero**
  `fastapi`/`supabase`/`httpx` imports, enforced by `import-linter`
  (`tool.importlinter` in `pyproject.toml`), not by convention. `src/app/cli.py` is a second,
  independent consumer of the same `PolicyEngine` with no HTTP anywhere in the path — proof the
  boundary is real, not just declared. Exits at 403/404/500.
- **Domain invariants** (`src/app/invariants/` + Postgres functions) — *would this leave the
  system in a valid state?* Counting rules like "not the last super-admin" that Cedar cannot
  express, since Cedar evaluates one `(principal, action, resource)` tuple with no aggregate view
  of other rows. Enforced as Postgres functions, not Python, because PostgREST gives each request
  its own transaction — a Python-side count-then-delete would race. Exits at 409.

Route handlers never branch on role; every guarded route carries a single
`Depends(requires(Action, ResourceRef))`.

## Why Cedar

Alternatives considered:

- **Hand-rolled RBAC grant matrix** — simplest, but no `forbid` semantics, so the API-key
  restriction becomes branching logic in a resolver: a second permission path that can drift from
  the first.
- **ReBAC / Zanzibar tuples** — maximally flexible, disproportionate for this scope.
- **Cedar (chosen)** — `forbid` overrides `permit` unconditionally, so three of the brief's four
  "extras" (API-key governance restriction, password-protected exports, org-only exports) are each
  a single `forbid` policy with no new code path, composing without ordering logic and applying
  automatically to roles that don't exist yet. Validated by a pre-implementation spike (documented
  assumption #7 below records its one sharp edge).

## Roles are data, capabilities are code

`role_capabilities` joins roles to seeded `capabilities` rows; Cedar policies bind to
*capabilities* (`principal in resource.can_edit`), never to role names — Cedar never learns that
roles exist. The `auditor` role (view, not run) proves it: it exists as two `INSERT`s —

```sql
insert into roles (id, org_id, name, scope) values ('...', null, 'auditor', 'team');
insert into role_capabilities (role_id, capability) values ('...', 'view');
```

— zero policy edits, and appears in [`docs/DECISION_MATRIX.md`](docs/DECISION_MATRIX.md) with the
same enforcement guarantees as the built-in roles. Adding a *capability* is deliberately a code
change (new `Action`/`Capability` + policy): that is new security surface and should not be a
runtime operation. `POST /v1/orgs/{org_id}/roles` composes existing capabilities only, so runtime
role creation can never invent one.

## The documented assumptions

The brief leaves several edge cases undefined. Full rulings:

| # | Situation | Ruling |
|---|---|---|
| 1 | Removing/demoting the last org super-admin | Blocked (409) — prevents permanent lockout |
| 2 | User removed from an org | Cascades out of all that org's teams |
| 3 | Default team | Auto-created per org, all members auto-joined, cannot be deleted or left |
| 4 | Super-admin vs. team membership | Bypassed entirely within their own org |
| 5 | Resource invisible to principal | 404, not 403 (a 403 would leak existence) |
| 6 | Visible resource, forbidden action | 403 + correlation ID; `policy_id` to logs only |
| 7 | Cedar result with diagnostics errors | 500 regardless of decision — an errored `forbid` is skipped and can fail open |
| 8 | Anonymous / external users | May only `WorkflowRunExported`; never list, view, or edit |
| 9 | API key privileges | Scoped to one org, inherits owner's roles, minus all governance actions; unmapped/revoked/expired fail closed |
| 10 | Multi-org users | Org context derives from the resource, never a client-supplied header |
| 11 | Who may export | `editor` toggles publication; only `admin` sets password/org-only protection |
| 12 | Removing the last team admin | Blocked (409), unless done by an org super-admin |
| 13 | Super-admin and password-protected exports | The public endpoint requires the password from everyone, including super-admins |
| 14 | Workflow ownership | Belongs to exactly one team; org-wide resources live on the default team |
| 15 | Who may create a team | Any org member; the creator becomes that team's admin atomically |
| 16 | Capability rows | Seed data, never user-writable; `POST /v1/orgs/{org_id}/roles` composes existing capabilities only |
| 17 | Custom role name collisions across orgs | Permitted and isolated — keyed `(org_id, name, scope)` |
| 18 | Missing `workflow_exports` row | Treated as `exported=false, visibility=public, password_protected=false` |
| 19 | API key privileges, precisely | Read-and-run only — `workflow:write` and governance scopes are never seeded |
| 20 | Org removal that strands a team | Allowed; assumption #12's escape hatch (a super-admin can appoint a new admin) covers repair |

## Single enforcement point

Data access uses the `supabase-py` client with the **service role**, which bypasses Row-Level
Security by design. So RLS policies would be decorative here — writing them and calling it
defense-in-depth would be a false sense of having two layers where there is one. Stated plainly:
**the FastAPI application is the only thing between a request and the data.**

The compensating control: `tests/test_route_coverage.py` walks `app.routes` (recursively across
every included router) at import time and fails if any route lacks an authorization dependency and
is not in the explicit `PUBLIC_ROUTES` allowlist. Adding a public endpoint becomes a deliberate,
reviewable diff instead of a silent omission — the failure mode this guards against is exactly
"a developer forgot `requires(...)`," which is the actual mistake people make, not merely the
subset of its consequences that cross an org boundary.

| | Service-role client (chosen) | Restricted role + RLS |
|---|---|---|
| Stack | Idiomatic Supabase, one data path | Bypasses the Supabase client; needs `asyncpg` + per-transaction session GUCs |
| Layers of enforcement | One, explicitly | Two, but the second is coarse and drifts from the first |
| Blast radius of a missed check | Full — mitigated by the route-coverage test | Limited to within one organization |

## Fail-open, and how it's prevented

A pre-implementation spike found the sharp edge: when an applicable `forbid` policy is missing an
attribute it needs, Cedar **skips** that policy rather than denying — observed as `Allow, errors=1`
where the correct answer was `Deny`, because a matching `permit` was then free to win. Two
compensating rules close it:

1. **D6** — `engine.py` treats any non-empty `diagnostics.errors` as a 500, regardless of the
   decision, including `Allow`. A malformed entity must never masquerade as a legitimate
   `Deny`, and it must certainly never masquerade as an `Allow`.
2. **Entity totality** — the `EntityProvider` is tested to always populate every attribute a
   schema-declared action can read, so the missing-attribute case that triggers the hazard cannot
   occur in the first place; D6 is the backstop for a bug in that guarantee, not the primary
   defense.

## Query-time enforcement

`GET /v1/workflows` derives a SQL pre-filter from the caller's capability slice (already computed
for the authorization decision) — `team_id IN (...) OR org_id IN (...)` — so the database does not
return every row in the organization only to have most of them discarded. The pre-filter is
deliberately a superset: **the engine still rules on every row that comes back**, via
`authorize_batch`, so a pre-filter that is too broad is merely wasteful, while one that is too
narrow would silently hide rows the policy would have allowed. `tests/test_prefilter.py` asserts
the containment property directly — for a fixture corpus, the pre-filtered set is always a
superset of the engine-allowed set. Pagination is keyset-based with capped over-fetch/refill, done
*after* authorization, so page sizes stay predictable under denial.

## Performance

`packages/authz-core/src/authz_core/engine.py`'s `PolicyEngine.authorize()` is the part of the
authorization dependency that is measurable without a live deployment (Docker/Supabase are not
available in this sandbox, so end-to-end p50/p99 against the seeded dataset is **pending** a real
deployment). A micro-benchmark of 1,000 in-memory decisions, reusing the policy-matrix fixtures,
gives:

| Metric | Value |
|---|---|
| p50 | 0.64 ms |
| p95 | 0.70 ms |
| p99 | 0.86 ms |
| max | 1.86 ms |

This covers only the Cedar evaluation itself — not the entity-slice fetch that precedes it (see
below) or the business query that follows. Stated as a budget: the policy engine adds under a
millisecond; the dominant cost is expected to be the database round trip for the entity slice and
the query itself, which this benchmark deliberately excludes. `SupabaseEntityProvider` currently
calls the synchronous `supabase-py` `.execute()`, which blocks the event loop — worth moving to an
async client before p50/p99 under concurrent load can be trusted end-to-end.

## Zero staleness

Authorization state — roles, capabilities, memberships — never enters the JWT; it is resolved from
the database on every request. A role change or revocation is therefore effective on the **very
next request**, with no session invalidation, token blacklist, or propagation window to reason
about.

## Enterprise identity roadmap (not built)

None of this changes `authz-core` — identity lives in Supabase and authorization state never
enters the token, so every item below attaches at the identity edge only:

- **SSO (OIDC/SAML)** — an `identity_providers` table keyed by org and verified email domain, JIT
  provisioning on first login, and a `group_role_mappings` table translating IdP group assertions
  to roles.
- **SCIM 2.0 provisioning/directory sync** — `/scim/v2/Users` and `/scim/v2/Groups` map onto
  `profiles`/`org_memberships` and `teams`/`team_memberships`; a SCIM `DELETE` sets
  `profiles.disabled_at`. Deprovisioning is instant *because of* zero staleness above — no session
  cleanup, no propagation window.
- **On-behalf-of delegation** — the API-key model (`principal` inherits the owner's roles, minus
  governance actions, via `forbid`) generalizes directly: put the delegate in `context.actor`,
  keep `principal` as the subject, and reuse the same `forbid`-on-governance pattern.

## What was deliberately not built

| Item | Why deferred |
|---|---|
| Generation-counter slice cache | The query-time pre-filter removes the term that actually grows with tenant size; a cache would shave a constant off an already-cheap fetch. A short-TTL cache was explicitly rejected — it would trade away zero staleness for the length of the window, which is the one property an access-control system should be least willing to sell. The correct design, if ever needed, is invalidation-first: a `generation` counter per `(user, org)` bumped on every membership/role mutation, keyed into the cache, so a stale entry is unreachable rather than merely short-lived. |
| Policy matrix beyond ~40 cases | The matrix in [`docs/DECISION_MATRIX.md`](docs/DECISION_MATRIX.md) covers every role × action class and the four `forbid` extras; broadening it toward exhaustive is additional test-writing, not new design. |
| Standalone PDP extraction | `authz-core`'s package boundary and the CLI already prove reusability without a network hop; extracting a service behind gRPC/HTTP would only be justified by a second real consumer, which does not exist yet. |
| Disabled-user JWT revocation | `JWTAuthenticator` has a dormant check (`src/app/auth/jwt.py`) for `profiles.disabled_at`, but no `ProfileRepository` is wired in yet, so it never fires. Wiring one is a repository + one constructor argument. Zero staleness for role/permission changes (above) is unaffected — this gap is specific to disabling an account outright. |
| Audit log limitations | The log is at-most-once (a background write from `requires(...)`, not a two-phase commit) — not a compliance log of record. It records authorization decisions only, not authentication failures. Read-`Allow`s are not recorded, to bound write amplification on the hottest path. A resource entirely absent from the principal's slice yields a 404 with no audit row, since the request never reaches a decision. |

## Error semantics

| Condition | Status |
|---|---|
| No/invalid credentials on a protected route | 401 |
| Authenticated, resource not visible to principal | 404 |
| Authenticated, resource visible, action denied | 403 + correlation ID (`policy_id` to logs only) |
| Permission granted, but the operation breaks a domain invariant | 409 |
| Cedar result carries any `diagnostics.errors` — `Allow` or `Deny` | 500 |
| Pydantic validation failure | 422 |

Responses use RFC 9457 `application/problem+json`.

## Local development & testing

**What CI covers.** `uv run pytest` runs the unit suite (`ruff`, `mypy`, `lint-imports`, and tests).
It exercises `authz-core` thoroughly, but **stubs the entire `app ↔ Supabase/GoTrue` seam** —
`get_engine`, `get_entity_provider`, `get_audit_writer`, and `get_supabase` are overridden in tests.
The files under `tests/integration/` are intended-behaviour **skeletons** (they reference
`client`/`authed`/`jwt` fixtures that don't exist yet), so `pytest -m integration` does not run.
Net: the infra adapter, auth chain, and error/audit plumbing are not covered by automated tests —
verify changes there against a live stack using the runbook below.

**Running end-to-end against local Supabase.** Modern `supabase start` signs user JWTs with **ES256**
(asymmetric), so the app verifies them via JWKS (`SUPABASE_JWKS_URL`).

```bash
supabase start                         # Postgres + PostgREST + GoTrue (needs Docker)
supabase status -o env                 # copy API_URL, SERVICE_ROLE_KEY (legacy eyJ… key), JWT_SECRET, ANON_KEY into .env
supabase db reset                      # applies ALL migrations incl. the service_role grants (0500)
PYTHONPATH=src uv run uvicorn app.main:app --port 8000
```

`.env` must set `SUPABASE_JWKS_URL=$SUPABASE_URL/auth/v1/.well-known/jwks.json` (preset in
`.env.example`) or real user tokens won't verify. No demo accounts are seeded — create one via GoTrue
signup (auto-creates the `profiles` row via the `handle_new_user` trigger), insert an org membership
(see the Quickstart), then mint a token with `grant_type=password`. Insert teams with
`created_by = null` to skip the `team_creator_is_admin` trigger. Creating an organization
auto-creates its default `General` team (trigger `org_gets_default_team`), and every org member is
enrolled in it — the assignment's org-level shared team.

**One-command demo.** `scripts/dev_seed.sh` does all of that idempotently — creates three users
(super-admin, editor, viewer), seeds an org / two teams / two workflows, and prints a ready-to-use
access token for each. Then open Swagger at **http://127.0.0.1:8000/docs**, click **Authorize**, paste
a token, and call any endpoint from the UI. The endpoints are grouped and ordered as a walkthrough;
[`DEMO_SCRIPT.md`](DEMO_SCRIPT.md) is the api-by-api recording script (with the allow-vs-deny story
and full assignment-coverage map).

**Gotchas.**

- A local `.env` makes `tests/test_settings.py::test_settings_reject_missing_service_role_key` fail —
  pydantic-settings reads the file, so the "missing key" assertion no longer holds. CI has no `.env`;
  move it aside to reproduce CI locally.
- PostgREST embeds a **to-one** relationship (e.g. `workflow_exports`, whose PK *is* the FK) as a
  single **object**, or `null` when absent — never a list.
- `service_role` needs explicit table GRANTs (RLS is bypassed by design, so no default privileges);
  these ship in `supabase/migrations/20260820000500_service_role_grants.sql`.

## More detail

- [`docs/DECISION_MATRIX.md`](docs/DECISION_MATRIX.md) — every role × action × resource-state case, generated from the tests, not hand-written.
- [`docs/diagrams/request-flow.md`](docs/diagrams/request-flow.md), [`entity-policy-model.md`](docs/diagrams/entity-policy-model.md), [`erd.md`](docs/diagrams/erd.md).

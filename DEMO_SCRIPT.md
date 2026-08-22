# Demo script — recording walkthrough

A start-to-finish path for the demo video. It follows the numbered tag groups in
Swagger (`/docs`), which are ordered as this script. Every step says which **token**
to use and the **expected result**, so the allow-vs-deny story is on screen.

## 0. Setup (once, before recording)

```bash
# Terminal 1 — Supabase
supabase start
supabase db reset            # migrations + seed roles + service_role grants

# Terminal 2 — the service
PYTHONPATH=src uv run uvicorn app.main:app --port 8000

# Terminal 3 — seed demo data + get tokens
scripts/dev_seed.sh
```

`dev_seed.sh` creates three users and prints a token for each:

| User | Role | Can do |
|---|---|---|
| `demo@example.com` | org **super-admin** | everything in the org |
| `editor@example.com` | **editor** on Team One | view / edit / run / publish WF One |
| `viewer@example.com` | **viewer** on Team One | view / run WF One — **not** edit |

Resources it seeds: **WF One** (`33333333-…-31`) in *Team One*, **WF Two**
(`33333333-…-32`) in *Team Two* (neither editor nor viewer belongs to Team Two).

Open **http://127.0.0.1:8000/docs**. Click **Authorize** (top-right), paste a token
(no `Bearer ` prefix), and it's sent on every request until you log out. Re-run
`dev_seed.sh` for fresh tokens if they expire (~1h).

> **What is a workflow id for?** A workflow is the protected resource. The whole
> service exists to decide *who may view / edit / run / publish that id* — so the
> demo is: take one workflow id and show it behaving differently for different
> roles and for logged-out users.

---

## The walkthrough (API by API)

### 0 · Health
- `GET /health` → `200 {"status":"ok"}`. "Service is up."

### 1 · Organizations  *(authorize as SUPER-ADMIN)*
The assignment's **Organization** endpoints. Narrate: only a super-admin may manage org membership.
- `POST /v1/orgs/{org_id}/members` — add a user to the org. Use `org_id` = `11111111-…-11`. → **201**.
- `PATCH /v1/orgs/{org_id}/members/{user_id}` — change an org role (e.g. promote to `super_admin`). → **200**.
- `DELETE /v1/orgs/{org_id}/members/{user_id}` — remove a member. → **204**.
  - **Money shot (409):** try to remove/demote the *last* super-admin → **409 Conflict** ("would leave the org unmanageable"). This is a counting invariant Cedar can't express, enforced in Postgres.

### 2 · Teams
The assignment's **Teams** endpoints.
- *(super-admin)* `POST /v1/orgs/{org_id}/teams` — create a team. → **201** (creator becomes its admin).
- *(any member)* `GET /v1/orgs/{org_id}/teams` — list **all** teams in the org. Note the **General** team: it's the org's default team, auto-created with the org, and every org member belongs to it (assignment's "shared org-level team"). → **200**.
- *(any user)* `GET /v1/me/teams` — list the caller's teams + role. Authorize as **viewer**, then as **editor** — different results, same endpoint. → **200**.
- *(team admin / super-admin)* `POST /v1/teams/{team_id}/members` — add a user to Team One. → **201**.
- `DELETE /v1/teams/{team_id}/members/{user_id}` / `PATCH …/members/{user_id}` — remove / change team role. → **204 / 200**.
- `DELETE /v1/teams/{team_id}` — delete a team. → **204**; deleting the **General** default team → **409** (holds org-level shared resources).

### 3 · Workflows  *(the core allow/deny story)*
The assignment's **Workflow** endpoints. This is the heart of the demo — same id, different roles.
- *(editor)* `POST /v1/teams/{team_id}/workflows` — create a workflow in Team One. → **201**.
- `GET /v1/workflows` — **list what you can access.** Authorize as **super-admin** (sees WF One *and* WF Two) vs **viewer** (sees only WF One). Same endpoint, per-row authorized. → **200**.
- `GET /v1/workflows/{WF_ONE}`:
  - as **viewer** → **200** (viewer may view).
  - as **viewer**, `GET /v1/workflows/{WF_TWO}` → **404** — viewer isn't in Team Two, so its *existence is hidden* (not 403).
- `PUT /v1/workflows/{WF_ONE}` (edit):
  - as **editor** → **200**.
  - as **viewer** → **403** — visible, but no edit permission. *(This 403 vs the 404 above is the key distinction to narrate.)*
- `DELETE /v1/workflows/{id}` (delete):
  - as **viewer/editor** → **403**; as **super-admin** (or team admin) → **204**. Super-admin can delete any workflow in the org — "delete all resources regardless of team."
- `POST /v1/workflows/{WF_ONE}/executions` (run, logged-in):
  - as **viewer** → **201** (viewer may run).
- Logged-out: with **no token** (hit *Logout* in Authorize), `GET /v1/workflows/{WF_ONE}` → **401**.

### 4 · Publishing & external access  *(the "external user" + extra points 3 & 4)*
Answers "run by viewer/external user depending on whether it's exported."
- *(editor)* `PUT /v1/workflows/{WF_ONE}/export` with `{"visibility":"public"}` → **200** (`is_exported=true`).
- **Log out** (Authorize → Logout), then `POST /v1/public/workflows/{WF_ONE}/executions` (no token) → **201**. An external user can now run the *published* workflow.
- Before publishing (or on WF Two), the same anonymous run → **403/404**. Toggle to show the difference.
- **Password protection (extra point 3):** *(team admin)* `PUT /v1/workflows/{WF_ONE}/export/protection` with `{"password":"s3cret"}`. Then anonymous run → **403**; call `POST /v1/public/workflows/{WF_ONE}/access` with the password to get a token, pass it as `X-Workflow-Token` to the run endpoint → **201**.
- **Org-only (extra point 4):** publish with `{"visibility":"org_only"}` → an anonymous/other-org caller is denied; an org member may run it.

### 5 · API keys  *(extra point 2 — scoped machine identity)*
- *(super-admin)* `POST /v1/orgs/{org_id}/api-keys` with scopes `["workflow:run"]` → **201**, returns the key **once**.
- Narrate the ceiling: send the key as `X-API-Key` and run a workflow → **allowed**; but try a governance action (create a team / delete) with the same key → **denied**. An API key is deliberately *less* powerful than the owner's login.

### 6 · Roles (roles-as-data)
- *(super-admin)* `POST /v1/orgs/{org_id}/roles` composing existing capabilities → **201**. "Adding a role is data, not code."
- Name a capability that isn't seeded → **422**. "A role can never invent new security surface."

### 7 · Authorization (explain)
- `POST /v1/authz/explain` for a `(principal, action, resource)` → shows **ALLOW/DENY + the deciding Cedar `policy_id`**. This is the only place a policy_id is disclosed; everywhere else the client gets a correlation id. Great closing slide — it makes the decision engine legible.

---

## Assignment coverage (what maps to what)

| Assignment requirement | Endpoint | Swagger group |
|---|---|---|
| Teams — create a team | `POST /v1/orgs/{org_id}/teams` | 2 |
| Teams — list teams a user belongs to + role | `GET /v1/me/teams` | 2 |
| Teams — add user to team | `POST /v1/teams/{team_id}/members` | 2 |
| Teams — remove user from team | `DELETE /v1/teams/{team_id}/members/{user_id}` | 2 |
| Teams — default team (auto-created, all members belong) | trigger `org_gets_default_team` + `GET /v1/orgs/{org_id}/teams` | 2 |
| Bonus — list all teams in an org | `GET /v1/orgs/{org_id}/teams` | 2 |
| Bonus — delete a team / a workflow | `DELETE /v1/teams/{id}` · `DELETE /v1/workflows/{id}` | 2 · 3 |
| Org — add user to org | `POST /v1/orgs/{org_id}/members` | 1 |
| Org — delete user from org | `DELETE /v1/orgs/{org_id}/members/{user_id}` | 1 |
| Org — change org-level role | `PATCH /v1/orgs/{org_id}/members/{user_id}` | 1 |
| Workflow — list accessible | `GET /v1/workflows` | 3 |
| Workflow — create / update | `POST /v1/teams/{team_id}/workflows` · `PUT /v1/workflows/{id}` | 3 |
| Workflow — execute | `POST /v1/workflows/{id}/executions` | 3 |
| Workflow — execute exported | `POST /v1/public/workflows/{id}/executions` | 4 |
| **Extra 1** — real CRUD (not just boilerplate) | teams/workflows/members are backed by Supabase | 1–4 |
| **Extra 2** — API-key auth with a lower ceiling | `…/api-keys` + `X-API-Key` | 5 |
| **Extra 3** — password-protected published flows | `…/export/protection`, `…/public/…/access` | 4 |
| **Extra 4** — org-only published flows | `PUT …/export {"visibility":"org_only"}` | 4 |
| Bonus — change team role | `PATCH /v1/teams/{team_id}/members/{user_id}` | 2 |
| Bonus — runtime roles (roles-as-data) | `POST /v1/orgs/{org_id}/roles` | 6 |
| Bonus — decision transparency | `POST /v1/authz/explain` | 7 |

Every required endpoint is implemented and all four extra-point features are built.

## Design-video talking points (second recording)

- **Reusable outside HTTP** — `authz-core` is a separate package with zero web/db deps; `src/app/cli.py` and `uv run authz check …` prove the same engine runs with no HTTP. Import-linter enforces the boundary.
- **Adding a role is data; adding a capability is code** — roles compose seeded capabilities via table rows (group 6). Capabilities are the deliberate code-change surface.
- **Cedar decides, the app does crypto** — session facts (`auth_method`, `password_verified`, `api_key_scopes`, org) go in Cedar *context*; the app verifies passwords/keys and passes booleans in.
- **Layered errors** — 401 (who), 403/404 (may you / can you even see it), 409 (would it corrupt state), 500 (fail-closed on a Cedar diagnostics error). RFC 9457 `problem+json`.
- **Honest trade-offs** — service-role DB access with no decorative RLS; counting invariants in Postgres because each PostgREST request is its own transaction. See README §"Enforcement model" and the spec's assumptions.

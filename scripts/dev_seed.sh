#!/usr/bin/env bash
#
# dev_seed.sh — one-command demo setup for local Supabase.
#
# Idempotent. Creates three users that make the allow-vs-deny story obvious, plus
# an org, two teams, and two workflows, then prints a ready-to-use ES256 access
# token for each user and a copy-paste cheat sheet.
#
#   demo@example.com    org SUPER-ADMIN            → can do everything in the org
#   editor@example.com  EDITOR on "Team One"       → can view/edit/run/publish WF One
#   viewer@example.com  VIEWER on "Team One"       → can view/run WF One, but NOT edit
#
#   WF One  → Team One   (editor & viewer can see it)
#   WF Two  → Team Two   (neither editor nor viewer is a member → they get 404)
#
# Prerequisites: `supabase start` is running and `supabase db reset` has been run
# (migrations + service_role grants applied). Needs curl, jq, docker.
#
# Usage: scripts/dev_seed.sh
#
set -euo pipefail

PASSWORD="correct-horse-battery"
ORG_ID="11111111-1111-1111-1111-111111111111"
TEAM1="22222222-2222-2222-2222-222222222221"
TEAM2="22222222-2222-2222-2222-222222222222"
WF1="33333333-3333-3333-3333-333333333331"
WF2="33333333-3333-3333-3333-333333333332"
ROLE_SUPER_ADMIN="00000000-0000-0000-0000-000000000002"  # org
ROLE_EDITOR="00000000-0000-0000-0000-000000000012"        # team
ROLE_VIEWER="00000000-0000-0000-0000-000000000011"        # team

for bin in curl jq docker; do
  command -v "$bin" >/dev/null || { echo "error: '$bin' is required but not installed" >&2; exit 1; }
done

env_out="$(supabase status -o env 2>/dev/null)" || {
  echo "error: 'supabase status' failed — is 'supabase start' running?" >&2; exit 1
}
get() { sed -n "s/^$1=\"\(.*\)\"/\1/p" <<<"$env_out"; }
API_URL="$(get API_URL)"; ANON_KEY="$(get ANON_KEY)"
: "${API_URL:?could not read API_URL from supabase status}"
: "${ANON_KEY:?could not read ANON_KEY from supabase status}"

DB_CONTAINER="$(docker ps --format '{{.Names}}' | grep -m1 supabase_db || true)"
: "${DB_CONTAINER:?could not find the running supabase_db container}"
psql() { docker exec -i "$DB_CONTAINER" psql -U postgres -d postgres -v ON_ERROR_STOP=1 "$@"; }

# Create the user if needed, echo its uuid (idempotent).
ensure_user() {
  local email="$1" resp id
  resp="$(curl -s "$API_URL/auth/v1/signup" -H "apikey: $ANON_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"$PASSWORD\"}")"
  id="$(jq -r '.user.id // .id // empty' <<<"$resp")"
  [ -n "$id" ] || id="$(psql -tAc "select id from profiles where email = '$email' limit 1;" | tr -d '[:space:]')"
  [ -n "$id" ] || { echo "error: could not create/find $email. Response: $resp" >&2; exit 1; }
  echo "$id"
}

token_for() {
  curl -s "$API_URL/auth/v1/token?grant_type=password" -H "apikey: $ANON_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$1\",\"password\":\"$PASSWORD\"}" | jq -r '.access_token // empty'
}

echo "Supabase: $API_URL  (db: $DB_CONTAINER)"
ADMIN_ID="$(ensure_user demo@example.com)"
EDITOR_ID="$(ensure_user editor@example.com)"
VIEWER_ID="$(ensure_user viewer@example.com)"

psql >/dev/null <<SQL
insert into organizations (id, name) values ('$ORG_ID', 'Acme') on conflict (id) do nothing;
insert into teams (id, org_id, name, is_default, created_by) values
  ('$TEAM1', '$ORG_ID', 'Team One', false, null),
  ('$TEAM2', '$ORG_ID', 'Team Two', false, null) on conflict (id) do nothing;

insert into org_memberships (org_id, user_id, role_id) values
  ('$ORG_ID', '$ADMIN_ID', '$ROLE_SUPER_ADMIN') on conflict (org_id, user_id) do nothing;
insert into team_memberships (team_id, user_id, role_id) values
  ('$TEAM1', '$EDITOR_ID', '$ROLE_EDITOR'),
  ('$TEAM1', '$VIEWER_ID', '$ROLE_VIEWER') on conflict (team_id, user_id) do nothing;

insert into workflows (id, org_id, team_id, name) values
  ('$WF1', '$ORG_ID', '$TEAM1', 'WF One'),
  ('$WF2', '$ORG_ID', '$TEAM2', 'WF Two') on conflict (id) do nothing;
SQL

ADMIN_TOKEN="$(token_for demo@example.com)"
EDITOR_TOKEN="$(token_for editor@example.com)"
VIEWER_TOKEN="$(token_for viewer@example.com)"
for t in "$ADMIN_TOKEN" "$EDITOR_TOKEN" "$VIEWER_TOKEN"; do
  [ -n "$t" ] || { echo "error: failed to mint a token — is the user confirmed?" >&2; exit 1; }
done

cat <<EOF

╭───────────────────────────────────────────────────────────────────────────────╮
│ Seed complete. Org "Acme", Team One / Team Two, WF One (Team One) / WF Two (Two) │
╰───────────────────────────────────────────────────────────────────────────────╯

Workflow ids:   WF_ONE=$WF1   WF_TWO=$WF2

Tokens (valid ~1h). In Swagger http://127.0.0.1:8000/docs → Authorize → paste one:

── SUPER-ADMIN (demo@example.com) ──
$ADMIN_TOKEN

── EDITOR (editor@example.com) ──
$EDITOR_TOKEN

── VIEWER (viewer@example.com) ──
$VIEWER_TOKEN

Quick allow-vs-deny check from the shell:
  A=$ADMIN_TOKEN ; E=$EDITOR_TOKEN ; V=$VIEWER_TOKEN
  curl -s -o /dev/null -w "editor view WF One: %{http_code}\n"  localhost:8000/v1/workflows/$WF1 -H "Authorization: Bearer \$E"   # 200
  curl -s -o /dev/null -w "viewer edit WF One: %{http_code}\n"  -X PUT localhost:8000/v1/workflows/$WF1 -H "Authorization: Bearer \$V" -H "Content-Type: application/json" -d '{"name":"nope"}'   # 403
  curl -s -o /dev/null -w "viewer see WF Two:  %{http_code}\n"  localhost:8000/v1/workflows/$WF2 -H "Authorization: Bearer \$V"   # 404 (hidden)
  curl -s -o /dev/null -w "admin  see WF Two:  %{http_code}\n"  localhost:8000/v1/workflows/$WF2 -H "Authorization: Bearer \$A"   # 200 (org super-admin)

See DEMO_SCRIPT.md for the full recording walkthrough.
EOF

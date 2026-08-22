#!/usr/bin/env bash
#
# dev_seed.sh — one-command demo setup for local Supabase.
#
# Idempotent. Creates a demo user (org super-admin) plus an org, team, and
# workflow, then prints a ready-to-use ES256 access token and example requests.
# Pair with the Swagger "Authorize" button at http://127.0.0.1:8000/docs.
#
# Prerequisites: `supabase start` is running and `supabase db reset` has been run
# (so migrations + the service_role grants are applied). Needs curl, jq, docker.
#
# Usage:
#   scripts/dev_seed.sh                      # defaults: demo@example.com
#   EMAIL=you@x.com PASSWORD=secret123 scripts/dev_seed.sh
#
set -euo pipefail

EMAIL="${EMAIL:-demo@example.com}"
PASSWORD="${PASSWORD:-correct-horse-battery}"

# Fixed IDs so the script is idempotent and the printed URLs are stable.
ORG_ID="11111111-1111-1111-1111-111111111111"
TEAM_ID="22222222-2222-2222-2222-222222222221"
WF_ID="33333333-3333-3333-3333-333333333331"
SUPER_ADMIN_ROLE="00000000-0000-0000-0000-000000000002"

for bin in curl jq docker; do
  command -v "$bin" >/dev/null || { echo "error: '$bin' is required but not installed" >&2; exit 1; }
done

# --- resolve Supabase connection details from the CLI ------------------------
env_out="$(supabase status -o env 2>/dev/null)" || {
  echo "error: 'supabase status' failed — is 'supabase start' running?" >&2; exit 1
}
get() { sed -n "s/^$1=\"\(.*\)\"/\1/p" <<<"$env_out"; }
API_URL="$(get API_URL)"
ANON_KEY="$(get ANON_KEY)"
: "${API_URL:?could not read API_URL from supabase status}"
: "${ANON_KEY:?could not read ANON_KEY from supabase status}"

DB_CONTAINER="$(docker ps --format '{{.Names}}' | grep -m1 supabase_db || true)"
: "${DB_CONTAINER:?could not find the running supabase_db container}"
psql() { docker exec -i "$DB_CONTAINER" psql -U postgres -d postgres -v ON_ERROR_STOP=1 "$@"; }

echo "Supabase: $API_URL  (db: $DB_CONTAINER)"

# --- create the user (idempotent) --------------------------------------------
signup="$(curl -s "$API_URL/auth/v1/signup" -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
USER_ID="$(jq -r '.user.id // .id // empty' <<<"$signup")"
if [ -z "$USER_ID" ]; then
  # Already registered (or email confirmation on) — look the id up by email.
  USER_ID="$(psql -tAc "select id from profiles where email = '$EMAIL' limit 1;" | tr -d '[:space:]')"
fi
[ -n "$USER_ID" ] || { echo "error: could not create or find user '$EMAIL'. Response: $signup" >&2; exit 1; }
echo "User: $EMAIL  ($USER_ID)"

# --- bootstrap org / team / membership / workflow ----------------------------
psql >/dev/null <<SQL
insert into organizations (id, name) values ('$ORG_ID', 'Acme') on conflict (id) do nothing;
insert into teams (id, org_id, name, is_default, created_by)
  values ('$TEAM_ID', '$ORG_ID', 'Team One', false, null) on conflict (id) do nothing;
insert into org_memberships (org_id, user_id, role_id)
  values ('$ORG_ID', '$USER_ID', '$SUPER_ADMIN_ROLE') on conflict (org_id, user_id) do nothing;
insert into workflows (id, org_id, team_id, name)
  values ('$WF_ID', '$ORG_ID', '$TEAM_ID', 'WF One') on conflict (id) do nothing;
SQL
echo "Seeded: org=$ORG_ID team=$TEAM_ID workflow=$WF_ID (user is super_admin)"

# --- mint an access token (ES256, what the app verifies) ---------------------
TOKEN="$(curl -s "$API_URL/auth/v1/token?grant_type=password" -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq -r '.access_token // empty')"
[ -n "$TOKEN" ] || { echo "error: failed to obtain an access token for '$EMAIL'" >&2; exit 1; }

cat <<EOF

──────────────────────────────────────────────────────────────────────────────
Access token (valid ~1h). In Swagger http://127.0.0.1:8000/docs → "Authorize" →
paste this (no "Bearer " prefix needed):

$TOKEN

Try it from the shell:

  export TOKEN='$TOKEN'
  curl -s localhost:8000/v1/workflows/$WF_ID -H "Authorization: Bearer \$TOKEN" | jq
  curl -s localhost:8000/v1/workflows      -H "Authorization: Bearer \$TOKEN" | jq

Workflow id: $WF_ID
──────────────────────────────────────────────────────────────────────────────
EOF

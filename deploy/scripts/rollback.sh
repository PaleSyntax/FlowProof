#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${FLOWPROOF_SCHEMA_COMPATIBLE:-}" == "true" ]] || {
  echo "set FLOWPROOF_SCHEMA_COMPATIBLE=true only after reviewing schema compatibility" >&2; exit 2;
}
[[ -n "${FLOWPROOF_DEPLOY_STATE_FILE:-}" && -f "$FLOWPROOF_DEPLOY_STATE_FILE" ]] || {
  echo "FLOWPROOF_DEPLOY_STATE_FILE with prior image references is required" >&2; exit 2;
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

validate_state_file() {
  local key value
  declare -A values=()
  while IFS='=' read -r key value; do
    [[ -n "$key" && -n "$value" && "$value" != *[[:space:]]* ]] || {
      echo "invalid deployment state entry" >&2; exit 2;
    }
    case "$key" in
      FLOWPROOF_API_REPOSITORY_DIGEST|FLOWPROOF_WEB_REPOSITORY_DIGEST|FLOWPROOF_API_IMAGE_ID|FLOWPROOF_WEB_IMAGE_ID|DEPLOYED_AT|SCHEMA_REVISION) ;;
      *) echo "unexpected key in deployment state" >&2; exit 2 ;;
    esac
    [[ -z "${values[$key]:-}" ]] || { echo "duplicate key in deployment state: $key" >&2; exit 2; }
    values["$key"]="$value"
  done < "$FLOWPROOF_DEPLOY_STATE_FILE"
  for key in FLOWPROOF_API_REPOSITORY_DIGEST FLOWPROOF_WEB_REPOSITORY_DIGEST FLOWPROOF_API_IMAGE_ID FLOWPROOF_WEB_IMAGE_ID DEPLOYED_AT SCHEMA_REVISION; do
    [[ -n "${values[$key]:-}" ]] || { echo "missing required deployment state key: $key" >&2; exit 2; }
  done
  FLOWPROOF_API_IMAGE="${values[FLOWPROOF_API_REPOSITORY_DIGEST]}"
  FLOWPROOF_WEB_IMAGE="${values[FLOWPROOF_WEB_REPOSITORY_DIGEST]}"
  previous_api_id="${values[FLOWPROOF_API_IMAGE_ID]}"
  previous_web_id="${values[FLOWPROOF_WEB_IMAGE_ID]}"
  previous_schema="${values[SCHEMA_REVISION]}"
}

require_owner_file "$FLOWPROOF_DEPLOY_STATE_FILE" "deployment state"
validate_state_file
validate_image_reference "$FLOWPROOF_API_IMAGE" FLOWPROOF_API_REPOSITORY_DIGEST
validate_image_reference "$FLOWPROOF_WEB_IMAGE" FLOWPROOF_WEB_REPOSITORY_DIGEST
export FLOWPROOF_API_IMAGE FLOWPROOF_WEB_IMAGE
init_core_compose
current_schema="$("${COMPOSE[@]}" exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc 'SELECT version_num FROM alembic_version' | tr -d '\r\n')"
[[ "$current_schema" == "$previous_schema" ]] || { echo "rollback refuses a schema revision change" >&2; exit 2; }
"${COMPOSE[@]}" up -d --no-deps api scheduler alert-worker ops-watcher web
[[ "$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q api)")" == "$previous_api_id" ]] || { echo "API image ID was not restored" >&2; exit 1; }
[[ "$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q web)")" == "$previous_web_id" ]] || { echo "dashboard image ID was not restored" >&2; exit 1; }
wait_for_core_health
echo "application rollback restored recorded image IDs without changing database schema"

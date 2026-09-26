#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

with_n8n=false
[[ "${1:-}" == "--with-n8n" ]] && with_n8n=true
[[ -z "${1:-}" || "$with_n8n" == "true" ]] || { echo "usage: upgrade.sh [--with-n8n]" >&2; exit 2; }
bash "$root/deploy/scripts/static-preflight.sh" upgrade
init_core_compose
"${COMPOSE[@]}" up -d --wait postgres
"${COMPOSE[@]}" run --rm --no-deps migrate python -m flowproof.deployment database-preflight --mode upgrade
wait_for_core_health

state_file="$(realpath -m "$FLOWPROOF_DEPLOY_STATE_FILE")"
state_dir="$(dirname "$state_file")"
api_container="$("${COMPOSE[@]}" ps -q api)"
web_container="$("${COMPOSE[@]}" ps -q web)"
[[ -n "$api_container" && -n "$web_container" ]] || { echo "upgrade requires healthy API and dashboard containers" >&2; exit 2; }

resolve_reference() {
  local container="$1" image_id digest
  image_id="$(docker inspect --format '{{.Image}}' "$container")"
  digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image_id" | head -n 1 | tr -d '\r\n')"
  if [[ -n "$digest" ]]; then printf '%s\t%s' "$digest" "$image_id"; return; fi
  [[ "${FLOWPROOF_ALLOW_LOCAL_IMAGE_IDS:-false}" == "true" ]] || { echo "running image has no repository digest" >&2; exit 2; }
  printf '%s\t%s' "$image_id" "$image_id"
}

IFS=$'\t' read -r previous_api previous_api_id <<< "$(resolve_reference "$api_container")"
IFS=$'\t' read -r previous_web previous_web_id <<< "$(resolve_reference "$web_container")"
schema_revision="$("${COMPOSE[@]}" exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc 'SELECT version_num FROM alembic_version' | tr -d '\r\n')"
[[ -n "$schema_revision" ]] || { echo "upgrade requires a current Alembic revision" >&2; exit 2; }
state_tmp="$(mktemp "$state_dir/.flowproof-deploy-state.XXXXXX")"
chmod 600 "$state_tmp"
printf 'FLOWPROOF_API_REPOSITORY_DIGEST=%s\nFLOWPROOF_WEB_REPOSITORY_DIGEST=%s\nFLOWPROOF_API_IMAGE_ID=%s\nFLOWPROOF_WEB_IMAGE_ID=%s\nDEPLOYED_AT=%s\nSCHEMA_REVISION=%s\n' \
  "$previous_api" "$previous_web" "$previous_api_id" "$previous_web_id" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$schema_revision" > "$state_tmp"
mv -f -- "$state_tmp" "$state_file"

bash "$root/deploy/scripts/backup.sh"
"${COMPOSE[@]}" run --rm --no-deps migrate python -m flowproof.deployment migrate
"${COMPOSE[@]}" up -d --wait api scheduler alert-worker ops-watcher web
wait_for_core_health

if [[ "$with_n8n" == "true" ]]; then
  bash "$root/deploy/scripts/create-n8n-service-credential.sh"
  init_n8n_compose
  "${COMPOSE[@]}" up -d --wait n8n
  bash "$root/deploy/scripts/provision-n8n.sh"
fi

wait_for_core_health
echo "FlowProof core upgrade completed"

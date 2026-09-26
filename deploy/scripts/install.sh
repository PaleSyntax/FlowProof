#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

with_n8n=false
[[ "${1:-}" == "--with-n8n" ]] && with_n8n=true
[[ -z "${1:-}" || "$with_n8n" == "true" ]] || { echo "usage: install.sh [--with-n8n]" >&2; exit 2; }
bash "$root/deploy/scripts/static-preflight.sh" install
init_core_compose
"${COMPOSE[@]}" up -d --wait postgres
"${COMPOSE[@]}" run --rm --no-deps migrate python -m flowproof.deployment database-preflight --mode install
"${COMPOSE[@]}" run --rm --no-deps migrate python -m flowproof.deployment migrate
"${COMPOSE[@]}" up -d --wait api scheduler alert-worker ops-watcher web
wait_for_core_health

require_variable FLOWPROOF_INITIAL_ADMIN_NAME
require_variable FLOWPROOF_INITIAL_ADMIN_PASSWORD_FILE
require_owner_file "$FLOWPROOF_INITIAL_ADMIN_PASSWORD_FILE" "initial admin password"
"${COMPOSE[@]}" exec -T api python -m flowproof.identity bootstrap-admin --name "$FLOWPROOF_INITIAL_ADMIN_NAME" --password-stdin < "$FLOWPROOF_INITIAL_ADMIN_PASSWORD_FILE" >/dev/null

if [[ "$with_n8n" == "true" ]]; then
  require_variable FLOWPROOF_N8N_SECRETS_DIR
  require_variable FLOWPROOF_N8N_HOST
  require_variable FLOWPROOF_N8N_EDITOR_BASE_URL
  require_variable FLOWPROOF_N8N_WEBHOOK_URL
  require_owner_file "$FLOWPROOF_N8N_SECRETS_DIR/n8n_encryption_key" "n8n encryption key"
  require_file_owner_uid "$FLOWPROOF_N8N_SECRETS_DIR/n8n_encryption_key" "n8n encryption key" "${FLOWPROOF_N8N_SECRET_UID:-1000}"
  bash "$root/deploy/scripts/create-n8n-service-credential.sh"
  init_n8n_compose
  "${COMPOSE[@]}" up -d --wait n8n
  bash "$root/deploy/scripts/manage-n8n-service-credential.sh" resume
fi

wait_for_core_health
echo "fresh FlowProof core install completed"

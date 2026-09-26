#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

mode="${1:?usage: static-preflight.sh install|upgrade}"
[[ "$mode" == "install" || "$mode" == "upgrade" ]] || { echo "invalid deployment mode" >&2; exit 2; }

for name in FLOWPROOF_SECRETS_DIR FLOWPROOF_API_IMAGE FLOWPROOF_WEB_IMAGE POSTGRES_DB POSTGRES_USER FLOWPROOF_ACCOUNTING_URL FLOWPROOF_CORS_ORIGIN FLOWPROOF_DEPLOY_STATE_FILE FLOWPROOF_BACKUP_DIR; do
  require_variable "$name"
done
validate_image_reference "$FLOWPROOF_API_IMAGE" FLOWPROOF_API_IMAGE
validate_image_reference "$FLOWPROOF_WEB_IMAGE" FLOWPROOF_WEB_IMAGE

for secret in token_pepper postgres_password alert_webhook_url; do
  path="$FLOWPROOF_SECRETS_DIR/$secret"
  require_owner_file "$path" "$secret"
  require_file_owner_uid "$path" "$secret" "${FLOWPROOF_APP_SECRET_UID:-10001}"
  if grep -Eqi '(placeholder|replace|changeme|ci-only)' "$path"; then
    echo "owner secret contains a placeholder: $secret" >&2; exit 2
  fi
done

state_dir="$(dirname "$(realpath -m "$FLOWPROOF_DEPLOY_STATE_FILE")")"
ensure_private_directory "$state_dir" "deployment state directory"
ensure_private_directory "$(realpath -m "$FLOWPROOF_BACKUP_DIR")" "backup directory"

init_core_compose
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" run --rm --no-deps migrate python -m flowproof.deployment static-preflight
printf '{"status":"static_preflight_script_ok","mode":"%s"}\n' "$mode"

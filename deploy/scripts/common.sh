#!/usr/bin/env bash
# Shared fail-closed helpers for FlowProof-owned deployment scripts.

deployment_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

init_core_compose() {
  local root
  root="$(deployment_root)"
  COMPOSE=(docker compose)
  [[ -n "${FLOWPROOF_COMPOSE_PROJECT_NAME:-}" ]] && COMPOSE+=(--project-name "$FLOWPROOF_COMPOSE_PROJECT_NAME")
  [[ -n "${FLOWPROOF_ENV_FILE:-}" ]] && COMPOSE+=(--env-file "$FLOWPROOF_ENV_FILE")
  local files="${FLOWPROOF_CORE_COMPOSE_FILES:-${FLOWPROOF_COMPOSE_FILES:-docker-compose.production.yml}}"
  local file
  IFS=':' read -r -a file_list <<< "$files"
  for file in "${file_list[@]}"; do COMPOSE+=(-f "$root/$file"); done
}

init_n8n_compose() {
  init_core_compose
  COMPOSE+=(-f "$(deployment_root)/docker-compose.integration-n8n.yml" --profile n8n)
}

require_variable() {
  local name="$1"
  [[ -n "${!name:-}" ]] || { echo "missing required deployment variable: $name" >&2; exit 2; }
}

require_owner_file() {
  local path="$1" label="$2" permissions
  [[ -f "$path" && -s "$path" ]] || { echo "missing or empty owner secret: $label" >&2; exit 2; }
  permissions="$(stat -c '%a' "$path")"
  [[ "$permissions" == "600" || "$permissions" == "400" ]] || {
    echo "owner secret must be 0400 or 0600: $label" >&2; exit 2;
  }
}

require_file_owner_uid() {
  local path="$1" label="$2" expected_uid="$3" actual_uid
  actual_uid="$(stat -c '%u' "$path")"
  [[ "$actual_uid" == "$expected_uid" ]] || {
    echo "$label must be owned by UID $expected_uid" >&2; exit 2;
  }
}

ensure_private_directory() {
  local path="$1" label="$2" permissions
  [[ "$path" != "/" ]] || { echo "$label must not be the filesystem root" >&2; exit 2; }
  mkdir -p "$path"
  chmod 700 "$path"
  permissions="$(stat -c '%a' "$path")"
  [[ "$permissions" == "700" ]] || { echo "$label must be owner-only" >&2; exit 2; }
}

validate_image_reference() {
  local value="$1" label="$2"
  if [[ "$value" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ ]]; then return 0; fi
  if [[ "${FLOWPROOF_ALLOW_LOCAL_IMAGE_IDS:-false}" == "true" && "$value" =~ ^sha256:[a-f0-9]{64}$ ]]; then return 0; fi
  echo "$label must be an immutable repository digest" >&2
  exit 2
}

health_url() {
  printf '%s' "${FLOWPROOF_API_HEALTH_URL:-http://${FLOWPROOF_API_BIND:-127.0.0.1}:${FLOWPROOF_API_PORT:-8000}}"
}

wait_for_core_health() {
  local url attempts delay_seconds attempt
  url="$(health_url)"
  attempts="${FLOWPROOF_CORE_HEALTH_ATTEMPTS:-30}"
  delay_seconds="${FLOWPROOF_CORE_HEALTH_DELAY_SECONDS:-2}"
  [[ "$attempts" =~ ^[1-9][0-9]*$ && "$delay_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "core health retry settings must be positive integers" >&2; return 2;
  }
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if curl --fail --silent --show-error "$url/health/live" >/dev/null \
      && curl --fail --silent --show-error "$url/health/ready" >/dev/null; then
      return 0
    fi
    sleep "$delay_seconds"
  done
  echo "core health checks did not succeed after ${attempts} attempts" >&2
  return 1
}

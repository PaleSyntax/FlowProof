#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Import the fixed least-privilege FlowProof credential and deterministic
# workflow IDs. The raw service token exists only in the owner secret file and
# in a short-lived import file; n8n encrypts the credential with its own key.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"
init_n8n_compose

docker_exec() {
  # Git Bash otherwise rewrites container paths such as /tmp/... into C:/... .
  docker exec "$@"
}

copy_file_to_container() {
  local source_path="$1" container_path="$2"
  # Streaming avoids docker cp's Windows target-path conversion. The source is
  # owner-readable and the destination is a short-lived container tmpfs file.
  docker exec -i "$container" sh -c "cat > '$container_path'" < "$source_path"
}

n8n_cli() {
  # docker compose exec starts a new process, so it does not inherit the
  # secret-derived exports of PID 1. Reconstruct them only for this one CLI
  # process; n8n encrypts imported credential data before it reaches PostgreSQL.
  # shellcheck disable=SC2016 # The remote shell expands its own secret paths and "$@".
  "${COMPOSE[@]}" exec -T n8n sh -ec '
    export N8N_ENCRYPTION_KEY="$(cat /run/secrets/n8n_encryption_key)"
    exec n8n "$@"
  ' n8n "$@"
}

n8n_cli_with_busy_retry() {
  local retries delay_seconds attempt diagnostic
  retries="${FLOWPROOF_N8N_CLI_BUSY_RETRIES:-5}"
  delay_seconds="${FLOWPROOF_N8N_CLI_BUSY_DELAY_SECONDS:-2}"
  [[ "$retries" =~ ^[1-9][0-9]*$ && "$delay_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "n8n CLI busy retry settings must be positive integers" >&2
    return 2
  }
  diagnostic="$temporary/n8n-cli-output.log"
  : > "$diagnostic"
  chmod 600 "$diagnostic"
  for ((attempt = 1; attempt <= retries; attempt++)); do
    if n8n_cli "$@" >"$diagnostic" 2>&1; then
      rm -f -- "$diagnostic"
      return 0
    fi
    if ! grep -Fq "SQLITE_BUSY: database is locked" "$diagnostic" || ((attempt == retries)); then
      cat "$diagnostic" >&2
      rm -f -- "$diagnostic"
      return 1
    fi
    echo "n8n CLI database busy; retrying attempt $((attempt + 1))/$retries" >&2
    sleep "$delay_seconds"
  done
}

secret_dir="${FLOWPROOF_SECRETS_DIR:?FLOWPROOF_SECRETS_DIR is required}"
token_file="${FLOWPROOF_N8N_TOKEN_FILE:-$secret_dir/n8n_flowproof_token}"
[[ -f "$token_file" && -s "$token_file" ]] || {
  echo "missing or empty n8n service token secret" >&2; exit 2;
}
[[ "$(stat -c '%a' "$token_file")" =~ ^(400|600)$ ]] || {
  echo "n8n service token secret must be owner-only (0400 or 0600)" >&2; exit 2;
}

container="$("${COMPOSE[@]}" ps -q n8n)"
[[ -n "$container" ]] || { echo "n8n must be running before provisioning" >&2; exit 2; }
"${COMPOSE[@]}" exec -T n8n node -e \
  "fetch('http://127.0.0.1:5678/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

token="$(tr -d '\r\n' < "$token_file")"
[[ "$token" =~ ^[A-Za-z0-9._~-]{24,}$ ]] || {
  echo "n8n service token has an unexpected format" >&2; exit 2;
}

# Validate the owner-provided token through stdin. It is not placed in an
# environment, Docker inspect metadata, command line, log, or shell history.
# shellcheck disable=SC2016 # Node reads its stdin inside the container.
printf '%s' "$token" | "${COMPOSE[@]}" exec -T n8n node -e '
const fs = require("node:fs");
const token = fs.readFileSync(0, "utf8");
const expected = ["events:write", "recovery:execute", "recovery:verify"];
fetch("http://api:8000/api/v1/auth/me", {headers: {Authorization: `Bearer ${token}`}})
  .then(async (response) => {
    const payload = await response.json().catch(() => ({}));
    const principal = payload.principal || {};
    const actual = Array.isArray(principal.scopes) ? [...principal.scopes].sort() : [];
    if (!response.ok || principal.kind !== "service" || actual.join(",") !== expected.join(",")) process.exit(1);
  })
  .catch(() => process.exit(1));
' || { echo "n8n service token is invalid or exceeds the fixed scope envelope" >&2; exit 2; }

temporary="$(mktemp -d)"
credential_file="$temporary/flowproof-api-service-account.json"
# Double slash preserves an absolute container path when this script is run by
# Git Bash, whose automatic conversion otherwise rewrites /tmp to C:/... .
remote_dir="//tmp/flowproof-provision"
# shellcheck disable=SC2329 # Called indirectly by the EXIT trap below.
cleanup() {
  # shellcheck disable=SC2317 # Called indirectly by the EXIT trap below.
  rm -rf -- "$temporary"
  # shellcheck disable=SC2317 # Called indirectly by the EXIT trap below.
  docker_exec "$container" rm -rf -- "$remote_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '[{"id":"flowproof-api-service-account","name":"FlowProof API service account","type":"httpHeaderAuth","data":{"name":"Authorization","value":"Bearer %s"}}]\n' "$token" > "$credential_file"
unset token
chmod 600 "$credential_file"

docker_exec "$container" mkdir -p "$remote_dir/workflows"
copy_file_to_container "$credential_file" "$remote_dir/flowproof-api-service-account.json"
for workflow in "$root"/workflows/*.json; do
  copy_file_to_container "$workflow" "$remote_dir/workflows/$(basename "$workflow")"
done

# n8n 2.30.5 upserts credentials and workflows by their fixed IDs, so reruns
# update only the FlowProof-managed records and never create duplicate imports.
n8n_cli_with_busy_retry import:credentials \
  --input="$remote_dir/flowproof-api-service-account.json"
n8n_cli_with_busy_retry import:workflow --separate --input="$remote_dir/workflows"
for workflow_id in flowproof-invoice-intake flowproof-invoice-approval flowproof-invoice-recovery; do
  n8n_cli_with_busy_retry publish:workflow --id="$workflow_id"
done

"${COMPOSE[@]}" restart n8n
for _ in {1..45}; do
  if "${COMPOSE[@]}" exec -T n8n node -e \
    "fetch('http://127.0.0.1:5678/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"; then
    echo "n8n credential and FlowProof workflows provisioned with the fixed service scope envelope"
    exit 0
  fi
  sleep 2
done

echo "n8n did not become healthy after provisioning restart" >&2
exit 1

#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# The n8n credential is a two-phase replacement: its raw value is never
# recoverable after issuance, so a durable public state is written before the
# API transaction and the active file is not touched before workflow evidence.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

command_name="${1:-}"
[[ $# -eq 1 && "$command_name" =~ ^(status|start|resume|abort|finalize)$ ]] || {
  echo "usage: manage-n8n-service-credential.sh {status|start|resume|abort|finalize}" >&2
  exit 2
}

require_variable FLOWPROOF_SECRETS_DIR
token_file="${FLOWPROOF_N8N_TOKEN_FILE:-$FLOWPROOF_SECRETS_DIR/n8n_flowproof_token}"
token_dir="$(dirname "$(realpath -m "$token_file")")"
ensure_private_directory "$token_dir" "n8n credential directory"
replacement_token_file="${FLOWPROOF_N8N_REPLACEMENT_TOKEN_FILE:-$token_dir/.n8n_flowproof_replacement_token}"
superseded_token_file="${FLOWPROOF_N8N_SUPERSEDED_TOKEN_FILE:-$token_dir/.n8n_flowproof_superseded_token}"
credential_state_file="${FLOWPROOF_N8N_CREDENTIAL_STATE_FILE:-$token_dir/n8n_flowproof_credential_state.json}"
evidence_file="${FLOWPROOF_N8N_CREDENTIAL_EVIDENCE_FILE:-$token_dir/n8n-credential-replacement.json}"
lifecycle_lock_file="${FLOWPROOF_N8N_CREDENTIAL_LOCK_FILE:-${credential_state_file}.lock}"
credential_ttl_seconds="${FLOWPROOF_N8N_CREDENTIAL_TTL_SECONDS:-2592000}"
expiry_alert_seconds="${FLOWPROOF_CREDENTIAL_EXPIRY_ALERT_SECONDS:-604800}"
[[ "$credential_ttl_seconds" =~ ^[1-9][0-9]*$ && "$expiry_alert_seconds" =~ ^[1-9][0-9]*$ && "$expiry_alert_seconds" -lt "$credential_ttl_seconds" ]] || {
  echo "n8n credential lifetime and expiry alert threshold must be positive, with warning shorter than TTL" >&2
  exit 2
}
host_python="${FLOWPROOF_PYTHON_EXECUTABLE:-}"
if [[ -z "$host_python" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    host_python="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    host_python="$(command -v python)"
  else
    echo "a host Python interpreter is required for n8n credential state handling" >&2
    exit 2
  fi
fi
python3() { "$host_python" "$@"; }
state_tool=(python3 "$root/scripts/n8n_credential_state.py")
init_core_compose

case "${FLOWPROOF_N8N_FAILURE_INJECT:-}" in
  ""|after_credential_db_commit|after_activation_state_transition|after_active_token_file_switch|after_superseded_credential_revoke) ;;
  *)
    echo "unsupported n8n credential failure injection point" >&2
    exit 2
    ;;
esac

acquire_lifecycle_lock() {
  local lock_dir lifecycle_lock_fd permissions
  command -v flock >/dev/null 2>&1 || {
    echo "flock is required for n8n credential lifecycle operations on a production Linux host" >&2
    exit 2
  }
  lock_dir="$(dirname "$(realpath -m "$lifecycle_lock_file")")"
  ensure_private_directory "$lock_dir" "n8n credential lifecycle lock directory"
  if [[ -e "$lifecycle_lock_file" ]]; then
    [[ -f "$lifecycle_lock_file" ]] || {
      echo "n8n credential lifecycle lock must be a regular file" >&2
      exit 2
    }
    permissions="$(stat -c '%a' "$lifecycle_lock_file")"
    [[ "$permissions" == "600" ]] || {
      echo "n8n credential lifecycle lock must be owner-only (0600)" >&2
      exit 2
    }
  else
    umask 077
    : > "$lifecycle_lock_file"
    chmod 600 "$lifecycle_lock_file"
  fi
  exec {lifecycle_lock_fd}>"$lifecycle_lock_file"
  if [[ "$command_name" == "status" ]]; then
    if flock -s -n "$lifecycle_lock_fd"; then
      return
    fi
    echo "n8n credential status snapshot is busy; retry after the lifecycle operation exits" >&2
    exit 75
  fi
  if ! flock -n "$lifecycle_lock_fd"; then
    echo "another n8n credential lifecycle process holds the operation lock; retry after it exits" >&2
    exit 75
  fi
}

acquire_lifecycle_lock

api_cli() {
  "${COMPOSE[@]}" exec -T api python -m flowproof.identity "$@"
}

state_json() {
  "${state_tool[@]}" read --state-file "$credential_state_file"
}

state_value() {
  local state="$1" key="$2"
  printf '%s' "$state" | python3 -c 'import json, sys; value = json.load(sys.stdin)[sys.argv[1]]; print("" if value is None else value)' "$key"
}

service_status() {
  if [[ -n "${1:-}" ]]; then
    api_cli service-credential-status --name n8n-flowproof --operation-id "$1"
  else
    api_cli service-credential-status --name n8n-flowproof
  fi
}

status_count() {
  local status="$1" key="$2"
  printf '%s' "$status" | python3 -c 'import json, sys; print(json.load(sys.stdin)["counts"][sys.argv[1]])' "$key"
}

credential_rows() {
  local status="$1" wanted="$2"
  printf '%s' "$status" | python3 -c '
import json, sys
for credential in json.load(sys.stdin)["credentials"]:
    if credential["status"] == sys.argv[1]:
        print("{}\t{}\t{}".format(credential["credential_id"], credential["expires_at"] or "", credential["label"]))
' "$wanted"
}

operation_match() {
  local operation_id="$1" status rows count
  status="$(service_status "$operation_id")"
  rows="$(credential_rows "$status" unexpired_unrevoked)"
  count="$(printf '%s\n' "$rows" | sed '/^$/d' | wc -l | tr -d ' ')"
  [[ "$count" == "1" ]] || return 1
  printf '%s\n' "$rows"
}

credential_identity() {
  local source_file="$1"
  require_owner_file "$source_file" "n8n credential"
  "${COMPOSE[@]}" exec -T api python -c '
import json, sys, urllib.request
value = sys.stdin.read().strip()
request = urllib.request.Request("http://127.0.0.1:8000/api/v1/auth/me", headers={"Authorization": f"Bearer {value}"})
with urllib.request.urlopen(request, timeout=10) as response:
    principal = json.load(response)["principal"]
expected = ["events:write", "recovery:execute", "recovery:verify"]
if response.status != 200 or principal.get("kind") != "service" or sorted(principal.get("scopes", [])) != expected:
    raise SystemExit(1)
credential_id = principal.get("credential_id")
if not isinstance(credential_id, str) or not credential_id:
    raise SystemExit(1)
print(json.dumps({"credential_id": credential_id, "principal_id": principal["id"]}, sort_keys=True))
' < "$source_file"
}

credential_id_from_identity() {
  printf '%s' "$1" | python3 -c 'import json, sys; print(json.load(sys.stdin)["credential_id"])'
}

verify_revoked() {
  local source_file="$1"
  "${COMPOSE[@]}" exec -T api python -c '
import sys, urllib.error, urllib.request
value = sys.stdin.read().strip()
request = urllib.request.Request("http://127.0.0.1:8000/api/v1/auth/me", headers={"Authorization": f"Bearer {value}"})
try:
    urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as exc:
    raise SystemExit(0 if exc.code == 401 else 1)
raise SystemExit(1)
' < "$source_file"
}

copy_owner_file_atomically() {
  local source_file="$1" destination_file="$2" temporary
  temporary="$(mktemp "$token_dir/.n8n-credential.XXXXXX")"
  chmod 600 "$temporary"
  cp -- "$source_file" "$temporary"
  mv -f -- "$temporary" "$destination_file"
  chmod 600 "$destination_file"
}

remove_sensitive_file() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$path"
  else
    rm -f -- "$path"
  fi
}

inject_failure() {
  local point="$1"
  if [[ "${FLOWPROOF_N8N_FAILURE_INJECT:-}" == "$point" ]]; then
    echo "failure injection: $point" >&2
    exit 75
  fi
}

credential_file_matches_replacement() {
  local source_file="$1" replacement_credential_id="$2" identity
  [[ -f "$source_file" ]] || return 1
  if ! identity="$(credential_identity "$source_file")"; then
    return 1
  fi
  [[ "$(credential_id_from_identity "$identity")" == "$replacement_credential_id" ]]
}

activate_replacement_from_staging() {
  local replacement_credential_id="$1"
  credential_file_matches_replacement "$replacement_token_file" "$replacement_credential_id" || {
    echo "replacement activation cannot proceed: the owner-only staging credential does not authenticate as the durable replacement; do not revoke the superseded credential" >&2
    exit 2
  }
  copy_owner_file_atomically "$replacement_token_file" "$token_file"
  credential_file_matches_replacement "$token_file" "$replacement_credential_id" || {
    echo "replacement activation cannot be confirmed after the atomic file switch; do not revoke the superseded credential" >&2
    exit 2
  }
  inject_failure after_active_token_file_switch
}

reconcile_replacement_activation() {
  local replacement_credential_id="$1" active_matches=false staging_matches=false
  if credential_file_matches_replacement "$token_file" "$replacement_credential_id"; then
    active_matches=true
  fi
  if [[ -e "$replacement_token_file" ]]; then
    if credential_file_matches_replacement "$replacement_token_file" "$replacement_credential_id"; then
      staging_matches=true
    else
      echo "replacement activation cannot be recovered: the staging credential does not authenticate as the durable replacement; do not revoke the superseded credential and use a separately reviewed recovery procedure" >&2
      exit 2
    fi
  fi
  if [[ "$active_matches" == "true" ]]; then
    if [[ "$staging_matches" == "true" ]]; then
      remove_sensitive_file "$replacement_token_file"
    fi
    return
  fi
  if [[ "$staging_matches" == "true" ]]; then
    activate_replacement_from_staging "$replacement_credential_id"
    remove_sensitive_file "$replacement_token_file"
    return
  fi
  echo "replacement activation cannot be recovered: neither active nor staging credential authenticates as the durable replacement; do not revoke the superseded credential and use a separately reviewed recovery procedure" >&2
  exit 2
}

write_evidence() {
  local status="$1" lifecycle="$2" superseded_bearer="$3" state
  local failure_injection_point="${FLOWPROOF_N8N_RECOVERY_FAILURE_INJECTION_POINT:-none}"
  local recovered_after_restart="${FLOWPROOF_N8N_RECOVERED_AFTER_RESTART:-false}"
  case "$failure_injection_point" in
    none|after_activation_state_transition|after_active_token_file_switch|after_superseded_credential_revoke) ;;
    *) echo "unsupported n8n credential recovery evidence point" >&2; exit 2 ;;
  esac
  [[ "$recovered_after_restart" == "true" || "$recovered_after_restart" == "false" ]] || {
    echo "n8n credential recovered-after-restart evidence must be true or false" >&2
    exit 2
  }
  [[ "$recovered_after_restart" == "false" || "$failure_injection_point" != "none" ]] || {
    echo "restart recovery evidence requires an injection point" >&2
    exit 2
  }
  state="$(state_json)"
  local evidence_dir temporary
  evidence_dir="$(dirname "$(realpath -m "$evidence_file")")"
  ensure_private_directory "$evidence_dir" "n8n credential evidence directory"
  temporary="$(mktemp "$evidence_dir/.n8n-credential-evidence.XXXXXX")"
  chmod 600 "$temporary"
  printf '%s' "$state" | python3 -c '
import json, pathlib, sys
state = json.load(sys.stdin)
status = json.loads(sys.argv[2])
lifecycle = sys.argv[3]
bearer = sys.argv[4]
failure_injection_point = sys.argv[5]
recovered_after_restart = sys.argv[6] == "true"
payload = {
  "operation_id": state["operation_id"],
  "principal_id": state["principal_id"],
  "replacement_credential_id": state["replacement_credential_id"],
  "superseded_credential_id": state["superseded_credential_id"],
  "replacement_expires_at": state["replacement_expires_at"],
  "operation_status": state["status"],
  "final_operation_status": state["status"],
  "lifecycle": lifecycle,
  "failure_injection_point": failure_injection_point,
  "recovered_after_restart": recovered_after_restart,
  "superseded_bearer_verification": bearer,
  "unexpired_unrevoked_count": status["counts"]["unexpired_unrevoked"],
  "expired_unrevoked_count": status["counts"]["expired_unrevoked"],
  "revoked_count": status["counts"]["revoked"],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
 ' "$temporary" "$status" "$lifecycle" "$superseded_bearer" "$failure_injection_point" "$recovered_after_restart"
  mv -f -- "$temporary" "$evidence_file"
  chmod 600 "$evidence_file"
}

archive_terminal_state() {
  [[ -f "$credential_state_file" ]] || return 0
  local state status operation_id archived
  state="$(state_json)"
  status="$(state_value "$state" status)"
  case "$status" in
    finalized|aborted)
      operation_id="$(state_value "$state" operation_id)"
      archived="${credential_state_file}.${operation_id}.${status}"
      mv -f -- "$credential_state_file" "$archived"
      chmod 600 "$archived"
      ;;
    *)
      echo "a replacement operation is still pending; use status, resume, abort, or finalize" >&2
      exit 2
      ;;
  esac
}

transition_state() {
  local status="$1"
  shift
  "${state_tool[@]}" transition --state-file "$credential_state_file" --status "$status" "$@" >/dev/null
}

stage_issued_value() {
  local issued="$1" temporary
  temporary="$(mktemp "$token_dir/.n8n-replacement.XXXXXX")"
  chmod 600 "$temporary"
  printf '%s' "$issued" | python3 -c '
import json, pathlib, sys
payload = json.load(sys.stdin)
value = payload.get("token")
if not isinstance(value, str) or len(value) < 24:
    raise SystemExit("issued credential has no usable value")
pathlib.Path(sys.argv[1]).write_text(value + "\n", encoding="utf-8")
' "$temporary"
  chmod 600 "$temporary"
  mv -f -- "$temporary" "$replacement_token_file"
  chmod 600 "$replacement_token_file"
}

issue_replacement() {
  local state operation_id principal_id issued replacement_credential_id replacement_expires_at
  state="$(state_json)"
  [[ "$(state_value "$state" status)" == "planned" ]] || return 0
  operation_id="$(state_value "$state" operation_id)"
  principal_id="$(state_value "$state" principal_id)"
  issued="$(api_cli issue-token --principal-id "$principal_id" --scope events:write --scope recovery:execute --scope recovery:verify --label n8n-flowproof --expires-in-seconds "$credential_ttl_seconds" --operation-id "$operation_id")"
  if [[ "${FLOWPROOF_N8N_FAILURE_INJECT:-}" == "after_credential_db_commit" ]]; then
    echo "failure injection: credential issued before local staging" >&2
    exit 75
  fi
  replacement_credential_id="$(printf '%s' "$issued" | python3 -c 'import json, sys; print(json.load(sys.stdin)["credential_id"])')"
  replacement_expires_at="$(printf '%s' "$issued" | python3 -c 'import json, sys; print(json.load(sys.stdin)["expires_at"])')"
  stage_issued_value "$issued"
  transition_state replacement_issued --replacement-credential-id "$replacement_credential_id" --replacement-expires-at "$replacement_expires_at"
  transition_state token_staged
}

reconcile_planned_operation() {
  local state operation_id match replacement_credential_id replacement_expires_at identity staged_credential_id
  state="$(state_json)"
  operation_id="$(state_value "$state" operation_id)"
  if ! match="$(operation_match "$operation_id")"; then
    local operation_status matched_count orphan_credential_id
    operation_status="$(service_status "$operation_id")"
    matched_count="$(printf '%s' "$operation_status" | python3 -c 'import json, sys; print(sum(c["status"] != "revoked" for c in json.load(sys.stdin)["credentials"]))')"
    if [[ "$matched_count" == "0" ]]; then
      issue_replacement
      return
    fi
    if [[ "$matched_count" == "1" ]]; then
      orphan_credential_id="$(printf '%s' "$operation_status" | python3 -c 'import json, sys; print(next(c["credential_id"] for c in json.load(sys.stdin)["credentials"] if c["status"] != "revoked"))')"
      api_cli remediate-orphan-credential --credential-id "$orphan_credential_id" --operation-id "$operation_id" >/dev/null
      transition_state aborted
      write_evidence "$(service_status)" "orphan_remediated_without_raw_value" "not_attempted"
      remove_sensitive_file "$replacement_token_file"
      echo "orphan replacement was revoked; start a new explicit operation" >&2
      return
    fi
    echo "multiple or non-operational credentials match replacement operation; refusing automatic recovery" >&2
    exit 2
  fi
  IFS=$'\t' read -r replacement_credential_id replacement_expires_at _ <<< "$match"
  if [[ -f "$replacement_token_file" ]] && identity="$(credential_identity "$replacement_token_file")"; then
    staged_credential_id="$(credential_id_from_identity "$identity")"
    if [[ "$staged_credential_id" == "$replacement_credential_id" ]]; then
      transition_state replacement_issued --replacement-credential-id "$replacement_credential_id" --replacement-expires-at "$replacement_expires_at"
      transition_state token_staged
      return
    fi
  fi
  api_cli remediate-orphan-credential --credential-id "$replacement_credential_id" --operation-id "$operation_id" >/dev/null
  transition_state aborted
  write_evidence "$(service_status)" "orphan_remediated_without_raw_value" "not_attempted"
  remove_sensitive_file "$replacement_token_file"
  echo "orphan replacement was revoked; start a new explicit operation" >&2
}

start_operation() {
  archive_terminal_state
  local created principal_id status unexpired expired superseded_credential_id="" active_identity active_credential_id
  created="$(api_cli create-service-account --name n8n-flowproof --scope events:write --scope recovery:execute --scope recovery:verify)"
  principal_id="$(printf '%s' "$created" | python3 -c 'import json, sys; print(json.load(sys.stdin)["principal"]["id"])')"
  status="$(service_status)"
  expired="$(credential_rows "$status" expired_unrevoked)"
  while IFS=$'\t' read -r credential_id _; do
    [[ -n "${credential_id:-}" ]] && api_cli revoke-token --credential-id "$credential_id" >/dev/null
  done <<< "$expired"
  status="$(service_status)"
  unexpired="$(status_count "$status" unexpired_unrevoked)"
  [[ "$unexpired" -le 1 ]] || { echo "multiple unexpired n8n credentials require manual remediation" >&2; exit 2; }
  if [[ "$unexpired" == "1" ]]; then
    if [[ "${FLOWPROOF_N8N_CREDENTIAL_ROTATE:-false}" != "true" ]]; then
      echo "existing n8n service credential remains valid"
      return 0
    fi
    superseded_credential_id="$(credential_rows "$status" unexpired_unrevoked | cut -f1)"
    if [[ -f "$token_file" ]] && active_identity="$(credential_identity "$token_file")"; then
      active_credential_id="$(credential_id_from_identity "$active_identity")"
      [[ "$active_credential_id" == "$superseded_credential_id" ]] || {
        echo "active token file does not match the public service credential record" >&2
        exit 2
      }
      copy_owner_file_atomically "$token_file" "$superseded_token_file"
    else
      echo "active token is unavailable; controlled recovery will revoke it only at finalize" >&2
    fi
  fi
  local operation_id now
  operation_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "${state_tool[@]}" create --state-file "$credential_state_file" --operation-id "$operation_id" --principal-id "$principal_id" --superseded-credential-id "$superseded_credential_id" --status planned --created-at "$now" >/dev/null
  issue_replacement
  echo "replacement staged; run resume after n8n import and real workflow verification"
}

resume_operation() {
  [[ -f "$credential_state_file" ]] || { echo "no n8n replacement operation exists" >&2; exit 2; }
  local state status replacement_credential_id identity
  state="$(state_json)"
  status="$(state_value "$state" status)"
  case "$status" in
    planned)
      reconcile_planned_operation
      ;;&
    replacement_issued)
      state="$(state_json)"
      replacement_credential_id="$(state_value "$state" replacement_credential_id)"
      [[ -f "$replacement_token_file" ]] || { echo "replacement value was not staged; aborting orphan" >&2; reconcile_planned_operation; return; }
      identity="$(credential_identity "$replacement_token_file")"
      [[ "$(credential_id_from_identity "$identity")" == "$replacement_credential_id" ]] || { echo "staged replacement does not match state" >&2; exit 2; }
      transition_state token_staged
      ;;&
    token_staged)
      FLOWPROOF_N8N_TOKEN_FILE="$replacement_token_file" bash "$root/deploy/scripts/provision-n8n.sh"
      transition_state imported_pending_verification
      ;;&
    imported_pending_verification)
      if [[ "${FLOWPROOF_N8N_WORKFLOW_VERIFIED:-false}" == "true" ]]; then
        transition_state verified_pending_activation
        echo "workflow evidence accepted; run finalize to activate and revoke"
      else
        echo "replacement imported; verify a real workflow, then rerun resume with FLOWPROOF_N8N_WORKFLOW_VERIFIED=true" >&2
      fi
      ;;
    verified_pending_activation|verified_pending_revocation)
      echo "verified replacement awaits explicit finalize"
      ;;
    finalized|aborted)
      echo "replacement operation is already $status"
      ;;
  esac
}

abort_operation() {
  [[ -f "$credential_state_file" ]] || { echo "no n8n replacement operation exists" >&2; exit 2; }
  local state status operation_id replacement_credential_id
  state="$(state_json)"
  status="$(state_value "$state" status)"
  case "$status" in
    planned|replacement_issued|token_staged|imported_pending_verification) ;;
    verified_pending_activation|verified_pending_revocation|finalized)
      echo "abort is prohibited after workflow verification; finalize or use a separately reviewed recovery procedure" >&2
      exit 2
      ;;
    aborted)
      echo "replacement operation is already aborted"
      return
      ;;
  esac
  operation_id="$(state_value "$state" operation_id)"
  replacement_credential_id="$(state_value "$state" replacement_credential_id)"
  if [[ -n "$replacement_credential_id" ]]; then
    api_cli remediate-orphan-credential --credential-id "$replacement_credential_id" --operation-id "$operation_id" >/dev/null
  fi
  remove_sensitive_file "$replacement_token_file"
  transition_state aborted
  write_evidence "$(service_status)" "operator_aborted" "not_attempted"
  echo "replacement operation aborted; superseded credential remains unchanged"
}

finalize_operation() {
  [[ -f "$credential_state_file" ]] || { echo "no n8n replacement operation exists" >&2; exit 2; }
  local state status replacement_credential_id superseded_credential_id superseded_bearer="not_applicable"
  state="$(state_json)"
  status="$(state_value "$state" status)"
  [[ "$status" == "verified_pending_activation" || "$status" == "verified_pending_revocation" ]] || {
    echo "finalize requires durable verified workflow evidence" >&2
    exit 2
  }
  replacement_credential_id="$(state_value "$state" replacement_credential_id)"
  superseded_credential_id="$(state_value "$state" superseded_credential_id)"
  if [[ "$status" == "verified_pending_activation" ]]; then
    credential_file_matches_replacement "$replacement_token_file" "$replacement_credential_id" || {
      echo "verified replacement staging credential does not authenticate as the durable replacement; do not revoke the superseded credential" >&2
      exit 2
    }
    transition_state verified_pending_revocation
    inject_failure after_activation_state_transition
  fi
  reconcile_replacement_activation "$replacement_credential_id"
  credential_file_matches_replacement "$token_file" "$replacement_credential_id" || {
    echo "replacement activation is not confirmed; do not revoke the superseded credential" >&2
    exit 2
  }
  if [[ -n "$superseded_credential_id" ]]; then
    api_cli revoke-token --credential-id "$superseded_credential_id" >/dev/null
    inject_failure after_superseded_credential_revoke
    if [[ -f "$superseded_token_file" ]]; then
      verify_revoked "$superseded_token_file" || { echo "superseded credential did not return 401" >&2; exit 1; }
      superseded_bearer="verified_401"
    else
      superseded_bearer="unavailable_lost_or_expired_value"
    fi
  fi
  local status_payload unexpired expired
  status_payload="$(service_status)"
  unexpired="$(status_count "$status_payload" unexpired_unrevoked)"
  expired="$(status_count "$status_payload" expired_unrevoked)"
  [[ "$unexpired" == "1" && "$expired" == "0" ]] || {
    echo "credential recovery did not converge to one unexpired credential and zero expired credentials" >&2
    exit 1
  }
  transition_state finalized
  write_evidence "$status_payload" "finalized" "$superseded_bearer"
  remove_sensitive_file "$replacement_token_file"
  remove_sensitive_file "$superseded_token_file"
  echo "replacement finalized with one unexpired n8n credential"
}

case "$command_name" in
  status)
    if [[ -f "$credential_state_file" ]]; then
      state_json
    else
      printf '%s\n' '{"operation_status":"none"}'
    fi
    service_status
    ;;
  start) start_operation ;;
  resume) resume_operation ;;
  abort) abort_operation ;;
  finalize) finalize_operation ;;
esac

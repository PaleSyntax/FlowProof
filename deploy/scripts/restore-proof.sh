#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${1:-}" == "--isolated" ]] || { echo "restore requires explicit --isolated flag" >&2; exit 2; }
archive="${2:?usage: restore-proof.sh --isolated /protected/flowproof-<timestamp>.dump}"
[[ -f "$archive" ]] || { echo "archive does not exist" >&2; exit 2; }
checksum_file="${archive%.dump}.sha256"
[[ -f "$checksum_file" ]] || { echo "missing checksum sidecar" >&2; exit 2; }
(cd "$(dirname "$archive")" && sha256sum --check "$(basename "$checksum_file")")
sentinels_file="${FLOWPROOF_RESTORE_SENTINELS_FILE:?FLOWPROOF_RESTORE_SENTINELS_FILE is required}"
[[ -f "$sentinels_file" && -s "$sentinels_file" ]] || {
  echo "restore sentinel manifest is required" >&2; exit 2;
}
[[ "$(stat -c '%a' "$sentinels_file")" =~ ^(400|600)$ ]] || {
  echo "restore sentinel manifest must be owner-only" >&2; exit 2;
}

project="flowproof-restore-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
container="$project-postgres"
volume="$project-data"
database="flowproof_restore"
password="$(openssl rand -hex 24)"
docker volume create "$volume" >/dev/null
docker run -d --name "$container" --network none -e POSTGRES_DB="$database" -e POSTGRES_USER=restore -e POSTGRES_PASSWORD="$password" -v "$volume:/var/lib/postgresql/data" postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777 >/dev/null
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
ready_checks=0
for _ in {1..60}; do
  if docker exec "$container" pg_isready -U restore -d "$database" >/dev/null 2>&1; then
    ready_checks=$((ready_checks + 1))
    [[ "$ready_checks" -ge 3 ]] && break
  else
    ready_checks=0
  fi
  sleep 1
done
[[ "$ready_checks" -ge 3 ]] || { echo "isolated restore database did not become stable" >&2; exit 1; }
docker cp "$archive" "$container:/tmp/restore.dump"
docker exec "$container" pg_restore -U restore -d "$database" --exit-on-error --no-owner --no-privileges /tmp/restore.dump
docker exec "$container" psql -U restore -d "$database" -v ON_ERROR_STOP=1 -Atc \
  "SELECT to_regclass('principals'), to_regclass('api_credentials'), to_regclass('auth_sessions'), to_regclass('security_audit_events'), to_regclass('business_events'), to_regclass('incidents'), to_regclass('recovery_plans'), to_regclass('deadline_jobs'), to_regclass('alert_outbox'), to_regclass('service_heartbeats'), to_regclass('operational_alert_states'), (SELECT version_num FROM alembic_version);" \
  | grep -Eq 'principals.*api_credentials.*auth_sessions.*security_audit_events.*business_events.*incidents.*recovery_plans.*deadline_jobs.*alert_outbox.*service_heartbeats.*operational_alert_states.*0010_release_groundwork_fencing'

while IFS=$'\t' read -r table_name sentinel_id expected_count; do
  [[ -n "$table_name" && -n "$sentinel_id" && "$expected_count" =~ ^[1-9][0-9]*$ ]] || {
    echo "invalid restore sentinel manifest row" >&2; exit 2;
  }
  case "$table_name" in
    principals|api_credentials|auth_sessions|security_audit_events|business_events|incidents|recovery_plans|deadline_jobs|alert_outbox|service_heartbeats|operational_alert_states) ;;
    *) echo "unexpected sentinel table: $table_name" >&2; exit 2 ;;
  esac
  sentinel_column="id"
  [[ "$table_name" == "service_heartbeats" ]] && sentinel_column="service"
  # psql does not expand variables in a command supplied with -c. Feed the
  # parameterized statement on stdin so the sentinel value stays a psql value,
  # rather than interpolating a restore-manifest value into SQL.
  actual_count="$(
    printf "SELECT count(*) FROM %s WHERE %s = :'sentinel_id';\\n" "$table_name" "$sentinel_column" \
      | docker exec -i "$container" psql -U restore -d "$database" -v ON_ERROR_STOP=1 -v sentinel_id="$sentinel_id" -At
  )"
  [[ "$actual_count" == "$expected_count" ]] || {
    echo "restore sentinel mismatch for $table_name" >&2; exit 1;
  }
done < "$sentinels_file"
echo "isolated restore database verified; audit volume retained: $volume"

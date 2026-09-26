#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

retain=14
if [[ "${1:-}" == "--retain" ]]; then
  retain="${2:?--retain needs a positive count}"
fi
[[ "$retain" =~ ^[1-9][0-9]*$ ]] || { echo "retention must be positive" >&2; exit 2; }
[[ -n "${FLOWPROOF_BACKUP_DIR:-}" ]] || { echo "FLOWPROOF_BACKUP_DIR is required" >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"
backup_dir="$(realpath -m "$FLOWPROOF_BACKUP_DIR")"
[[ "$backup_dir" != "/" ]] || { echo "backup directory must not be the filesystem root" >&2; exit 2; }
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
init_core_compose

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
stem="$backup_dir/flowproof-$timestamp"
dump="$stem.dump"
metadata="$stem.json"
partial_dump="$stem.dump.partial"
complete=false

cleanup_partial() {
  if [[ "$complete" != "true" ]]; then
    rm -f -- "$partial_dump" "$dump" "$stem.sha256" "$metadata"
  fi
}
trap cleanup_partial EXIT

"${COMPOSE[@]}" exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$partial_dump"
[[ -s "$partial_dump" ]] || { echo "pg_dump created an empty artifact" >&2; exit 1; }
mv -f -- "$partial_dump" "$dump"
checksum="$(sha256sum "$dump" | awk '{print $1}')"
printf '%s  %s\n' "$checksum" "$(basename "$dump")" > "$stem.sha256"
head="$("${COMPOSE[@]}" exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc 'SELECT version_num FROM alembic_version' | tr -d '\r\n')"
application_version="${FLOWPROOF_APPLICATION_VERSION:-0.6.0}"
source_image_revision="${FLOWPROOF_SOURCE_IMAGE_REVISION:-}"
if [[ -z "$source_image_revision" ]]; then
  api_container="$("${COMPOSE[@]}" ps -q api)"
  [[ -n "$api_container" ]] || { echo "API container is required to record backup provenance" >&2; exit 2; }
  source_image_revision="$(docker inspect --format '{{.Image}}' "$api_container")"
fi
printf '{"created_at":"%s","format":"pg_dump_custom","database":"%s","sha256":"%s","alembic_head":"%s","application_version":"%s","source_image_revision":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$POSTGRES_DB" "$checksum" "$head" "$application_version" "$source_image_revision" > "$metadata"

mapfile -t dumps < <(find "$backup_dir" -maxdepth 1 -type f -name 'flowproof-????????T??????Z.dump' -printf '%f\n' | sort)
if (( ${#dumps[@]} > retain )); then
  for old in "${dumps[@]:0:${#dumps[@]}-retain}"; do
    old_stem="$backup_dir/${old%.dump}"
    rm -f -- "$old_stem.dump" "$old_stem.sha256" "$old_stem.json"
  done
fi
complete=true
echo "backup created: $(basename "$dump")"

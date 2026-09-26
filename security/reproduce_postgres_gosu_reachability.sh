#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
output_dir="${1:-$root/reports/reproduction}"
if [[ "$output_dir" != /* && "$output_dir" != [A-Za-z]:/* ]]; then
  output_dir="$root/$output_dir"
fi
mkdir -p "$output_dir"

go_image="golang:1.24.6-alpine@sha256:c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d"
gosu_module="github.com/tianon/gosu"
gosu_query="6456aaa0f3c854d199d0f037f068eb97515b7513"
govulncheck_version="v1.1.4"
vulnerability_database="https://vuln.go.dev"
module_metadata="$output_dir/postgres-gosu-module-download.json"
raw="$output_dir/postgres-gosu-govulncheck.jsonl"
result="$output_dir/postgres-gosu-reproduction.json"
output_host="$output_dir"
if command -v cygpath >/dev/null 2>&1; then
  output_host="$(cygpath -w "$output_dir")"
fi

# Resolve the exact reviewed commit through the official Go module proxy. The
# client cannot fall back to Git or any other VCS, so no GitHub request occurs.
MSYS_NO_PATHCONV=1 docker run --rm \
  -e GOPROXY="https://proxy.golang.org" \
  -e GOSUMDB="sum.golang.org" \
  -e GOVCS="*:off" \
  -e GOPRIVATE="" \
  -e GONOSUMDB="" \
  -e GOSU_MODULE="$gosu_module" \
  -e GOSU_QUERY="$gosu_query" \
  -e GOVULNCHECK_VERSION="$govulncheck_version" \
  -e VULNERABILITY_DATABASE="$vulnerability_database" \
  -v "$output_host:/evidence:rw" \
  "$go_image" \
  sh -ec '
    go mod download -json "$GOSU_MODULE@$GOSU_QUERY" > /evidence/postgres-gosu-module-download.json
    module_dir="$(awk -F\" '\''/^[[:space:]]*"Dir":/ {print $4}'\'' /evidence/postgres-gosu-module-download.json)"
    test -n "$module_dir" && test -d "$module_dir"
    GOBIN=/tmp/bin go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
    actual_version="$(/tmp/bin/govulncheck -version | tr -d "\r")"
    case "$actual_version" in *"$GOVULNCHECK_VERSION"*) ;; *) exit 1 ;; esac
    cd "$module_dir"
    /tmp/bin/govulncheck \
      -db="$VULNERABILITY_DATABASE" \
      -json \
      ./... \
      > /evidence/postgres-gosu-govulncheck.jsonl
  '

python security/compare_postgres_gosu_reachability.py \
  --module-metadata "$module_metadata" \
  --raw "$raw" \
  --output "$result" \
  --evidence security/postgres-gosu-reachability.json \
  --govulncheck-version "$govulncheck_version" \
  --vulnerability-database "$vulnerability_database"

#!/usr/bin/env bash
set -Eeuo pipefail

# Compatibility entrypoint. The managed lifecycle writes durable state before
# issuance and never changes the active file while verification is pending.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

exec bash "$root/deploy/scripts/manage-n8n-service-credential.sh" start

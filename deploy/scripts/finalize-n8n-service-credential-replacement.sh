#!/usr/bin/env bash
set -Eeuo pipefail

# Compatibility entrypoint for the explicit, post-workflow replacement step.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=deploy/scripts/common.sh
source "$root/deploy/scripts/common.sh"

exec bash "$root/deploy/scripts/manage-n8n-service-credential.sh" finalize

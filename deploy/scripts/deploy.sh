#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:?usage: deploy.sh install|upgrade [--with-n8n]}"
shift
case "$mode" in
  install) exec bash "$root/deploy/scripts/install.sh" "$@" ;;
  upgrade) exec bash "$root/deploy/scripts/upgrade.sh" "$@" ;;
  *) echo "usage: deploy.sh install|upgrade [--with-n8n]" >&2; exit 2 ;;
esac

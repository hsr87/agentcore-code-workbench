#!/usr/bin/env bash
# Destroy platform, then compute. Storage is deliberately kept in a separate state.
# ./scripts/cleanup.sh [--apply]
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
APPLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=true; shift;;
    *) echo "unknown argument: $1" >&2; exit 1;;
  esac
done
for STAGE in platform foundation; do
  DIR="infra/terraform/$STAGE"
  terraform -chdir="$DIR" plan -destroy -out=destroy.tfplan
  if $APPLY; then
    terraform -chdir="$DIR" apply destroy.tfplan
    rm -f "$DIR/destroy.tfplan"
  fi
done
echo "Recordings remain managed by infra/terraform/storage."

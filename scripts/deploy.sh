#!/usr/bin/env bash
# Terraform deployment. Configure the matching terraform.tfvars first.
# ./scripts/deploy.sh --stage storage|foundation|platform [--apply]
# ./scripts/deploy.sh --stage images --tag <unique-image-tag> [--mirror-emulator]
set -euo pipefail
umask 077          # plan files contain every variable value in cleartext
cd "$(dirname "$0")/.."
STAGE="foundation"; APPLY=false; TAG=""; MIRROR=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage) STAGE="$2"; shift 2;;
    --apply) APPLY=true; shift;;
    --tag) TAG="$2"; shift 2;;
    --mirror-emulator) MIRROR=true; shift;;
    *) echo "unknown argument: $1 (see GUIDE.md)" >&2; exit 1;;
  esac
done
case "$STAGE" in
  storage|foundation|platform)
    DIR="infra/terraform/$STAGE"
    terraform -chdir="$DIR" init -input=false
    terraform -chdir="$DIR" plan -out=deploy.tfplan
    if $APPLY; then
      terraform -chdir="$DIR" apply deploy.tfplan
      rm -f "$DIR/deploy.tfplan"   # never re-apply a stale plan, and do not leave it on disk
    fi
    ;;
  images)
    [[ -n "$TAG" || "$MIRROR" == true ]] || { echo "--tag <sidecar tag> and/or --mirror-emulator is required (ECR tags are immutable)" >&2; exit 1; }
    ARGS=()
    [[ -n "$TAG" ]] && ARGS+=(--tag "$TAG")
    $MIRROR && ARGS+=(--mirror-emulator)
    python3 infra/build_images.py "${ARGS[@]}"
    ;;
  *) echo "stage must be storage | foundation | platform | images" >&2; exit 1;;
esac

#!/usr/bin/env bash
set -euo pipefail
IMAGE="$1"; OUT="$2"

GRYPE_CHECK_FOR_APP_UPDATE=false grype "docker:${IMAGE}" \
  --output "json=${OUT}/grype.json" \
  --only-fixed=false

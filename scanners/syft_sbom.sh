#!/usr/bin/env bash
# scanners/syft_sbom.sh
# Args: <image> <results_dir>

set -euo pipefail
IMAGE="$1"; OUT="$2"

SYFT_CHECK_FOR_APP_UPDATE=false syft "docker:${IMAGE}" \
  --output "cyclonedx-json=${OUT}/sbom.json"

#!/usr/bin/env bash
# scanners/dockle_scan.sh
# Args: <image> <results_dir>

set -euo pipefail
IMAGE="$1"; OUT="$2"

dockle \
  --format json \
  --output "${OUT}/dockle.json" \
  "$IMAGE" || true   # dockle exits non-zero on findings — that's expected

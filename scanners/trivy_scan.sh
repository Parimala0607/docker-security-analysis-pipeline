#!/usr/bin/env bash
set -euo pipefail
IMAGE="$1"; OUT="$2"

# NOTE: no --severity filter here. Grype reports all severities, so Trivy must
# too — otherwise the scanner-disagreement numbers are an artifact of config,
# not of the scanners. Severity filtering happens downstream in the report.
trivy image \
  --format json \
  --scanners vuln \
  --timeout 10m \
  --quiet \
  --output "${OUT}/trivy.json" \
  "$IMAGE"

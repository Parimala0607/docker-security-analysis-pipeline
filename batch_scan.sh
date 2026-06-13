#!/usr/bin/env bash
# batch_scan.sh — Scan all targets defined in config/settings.yaml
# Usage: ./batch_scan.sh

set -euo pipefail

RESULTS_DIR="results"
REPORTS_DIR="reports"
REMEDIATED_DIR="remediated"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

TARGETS=$(python3 -c "
import yaml
cfg = yaml.safe_load(open('config/settings.yaml'))
print('\n'.join(cfg['targets']))
")

echo "Clearing old generated outputs..."
mkdir -p "$RESULTS_DIR" "$REPORTS_DIR" "$REMEDIATED_DIR"
find "$RESULTS_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
find "$REPORTS_DIR" -maxdepth 1 -type f \( -name 'report_*.html' -o -name 'batch_report_*.html' \) -delete
find "$REMEDIATED_DIR" -maxdepth 1 -type f -name 'Dockerfile.*' -delete

echo "Starting batch scan for $(echo "$TARGETS" | wc -l) images..."

while IFS= read -r image; do
  echo "━━━ Scanning: $image"
  bash pipeline.sh "$image" || echo "WARN: $image failed, continuing..."
done <<< "$TARGETS"

python3 -m analysis.comparator
python3 -m reports.batch_report_generator "$RESULTS_DIR" "$TIMESTAMP"

echo "Batch complete. Aggregate report → reports/batch_report_${TIMESTAMP}.html"

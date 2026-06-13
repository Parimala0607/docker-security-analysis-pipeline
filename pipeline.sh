#!/usr/bin/env bash
# pipeline.sh — Master orchestrator
# Usage: ./pipeline.sh <image> [--skip-pull]
# Example: ./pipeline.sh nginx:1.21

set -euo pipefail

IMAGE="${1:?Usage: ./pipeline.sh <image>}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SAFE_NAME=$(echo "$IMAGE" | tr '/.:' '___')
RESULTS_DIR="results/${TIMESTAMP}_${SAFE_NAME}"
LOG_DIR="${RESULTS_DIR}/logs"
SCANNER_RETRIES="${SCANNER_RETRIES:-2}"

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
step() { echo -e "\n${CYAN}[$1/8]${NC} $2"; }
ok()   { echo -e "${GREEN}✓${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1" >&2; exit 1; }

run_scanner() {
  local name="$1"
  shift
  local log="${LOG_DIR}/${name}.log"
  local status_file="${LOG_DIR}/${name}.status"
  local attempt=1

  : > "$log"
  while (( attempt <= SCANNER_RETRIES + 1 )); do
    {
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${name} attempt ${attempt}"
      "$@"
    } >> "$log" 2>&1 && {
      echo "ok" > "$status_file"
      return 0
    }

    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${name} attempt ${attempt} failed" >> "$log"
    (( attempt++ ))
    if (( attempt <= SCANNER_RETRIES + 1 )); then
      sleep $(( attempt * 2 ))
    fi
  done

  echo "failed" > "$status_file"
  return 1
}

# ── Preflight ──────────────────────────────────────────────────────────────
for cmd in docker trivy grype dockle syft python3; do
  command -v "$cmd" &>/dev/null || err "Missing: $cmd — run scripts/install_tools.sh"
done

mkdir -p "$RESULTS_DIR" "$LOG_DIR"
echo -e "\n${CYAN}Docker Security Pipeline${NC}"
echo "Image   : $IMAGE"
echo "Results : $RESULTS_DIR"

# ── 1. Pull ────────────────────────────────────────────────────────────────
step 1 "Pulling image"
if [[ "${2:-}" != "--skip-pull" ]]; then
  if ! docker pull "$IMAGE" > "${LOG_DIR}/pull.log" 2>&1; then
    err "Image pull failed — see ${LOG_DIR}/pull.log"
  fi
else
  echo "Skipped pull for ${IMAGE}" > "${LOG_DIR}/pull.log"
fi
ok "Image ready"

python3 -m analysis.scan_metadata "$IMAGE" "$RESULTS_DIR"

# ── 2. Scan (parallel) ────────────────────────────────────────────────────
step 2 "Running scanners in parallel"
scanner_pids=()

run_scanner trivy  bash scanners/trivy_scan.sh  "$IMAGE" "$RESULTS_DIR" & scanner_pids+=($!)
run_scanner grype  bash scanners/grype_scan.sh  "$IMAGE" "$RESULTS_DIR" & scanner_pids+=($!)
run_scanner dockle bash scanners/dockle_scan.sh "$IMAGE" "$RESULTS_DIR" & scanner_pids+=($!)
run_scanner syft   bash scanners/syft_sbom.sh   "$IMAGE" "$RESULTS_DIR" & scanner_pids+=($!)

scan_failed=0
for pid in "${scanner_pids[@]}"; do
  if ! wait "$pid"; then
    scan_failed=1
  fi
done

python3 -m analysis.scanner_status "$RESULTS_DIR"
(( scan_failed == 0 )) || err "One or more scanners failed"
ok "All scanners complete"

# ── 3. Validate FP/FN ─────────────────────────────────────────────────────
step 3 "Validating false positives / negatives"
python3 -m analysis.fp_fn_validator "$RESULTS_DIR"
ok "Validation complete"

# ── 4. Enrich with EPSS + KEV ─────────────────────────────────────────────
step 4 "Enriching CVEs with EPSS + CISA KEV"
python3 -m analysis.epss_scorer "$RESULTS_DIR"
ok "Enrichment complete"

# ── 5. Coarse origin classification ────────────────────────────────────────
step 5 "Classifying finding origin"
python3 -m analysis.layer_attribution "$IMAGE" "$RESULTS_DIR"
ok "Origin classification complete"

# ── 6. Generate remediated Dockerfile ─────────────────────────────────────
step 6 "Generating hardened Dockerfile"
python3 -m remediation.dockerfile_generator "$IMAGE" "$RESULTS_DIR"
ok "Dockerfile generated → remediated/"

# ── 7. Policy gate ────────────────────────────────────────────────────────
step 7 "Evaluating risk policy"
python3 -m analysis.policy_gate "$RESULTS_DIR"
ok "Policy evaluation complete"

# ── 8. Report ─────────────────────────────────────────────────────────────
step 8 "Generating report"
python3 -m reports.report_generator "$IMAGE" "$RESULTS_DIR" "$TIMESTAMP"
ok "Report → reports/report_${TIMESTAMP}.html"

echo -e "\n${GREEN}Pipeline complete.${NC}"

# analysis/scanner_status.py
# Summarises per-scanner logs into scanner_status.json.
# Usage: python3 -m analysis.scanner_status <results_dir>

from __future__ import annotations

from pathlib import Path
import json
import sys


def collect(results_dir: Path) -> dict:
    log_dir = results_dir / "logs"
    scanners = ("trivy", "grype", "dockle", "syft")
    status = {}

    for scanner in scanners:
        log_path = log_dir / f"{scanner}.log"
        status_path = log_dir / f"{scanner}.status"
        state = status_path.read_text().strip() if status_path.exists() else "missing"
        status[scanner] = {
            "status": state,
            "log": str(log_path),
            "log_exists": log_path.exists(),
        }

    out_path = results_dir / "scanner_status.json"
    out_path.write_text(json.dumps(status, indent=2))
    return status


if __name__ == "__main__":
    collect(Path(sys.argv[1]))

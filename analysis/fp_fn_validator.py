# analysis/fp_fn_validator.py
# Cross-references Trivy and Grype to identify scanner disagreement
# Usage: python3 -m analysis.fp_fn_validator <results_dir>

from __future__ import annotations
from pathlib import Path
import json
import sys

from analysis.models import ValidationResult
from analysis.parsers import ids_from_trivy, ids_from_grype


def validate(results_dir: Path) -> ValidationResult:
    trivy = ids_from_trivy(results_dir / "trivy.json")
    grype = ids_from_grype(results_dir / "grype.json")

    result = ValidationResult(
        confirmed  = trivy & grype,
        trivy_only = trivy - grype,
        grype_only = grype - trivy,
    )

    (results_dir / "validation.json").write_text(
        json.dumps({
            "methodology": (
                "Set comparison of normalized CVE ids (Grype GHSA ids mapped to "
                "their related CVE where available) from Trivy and Grype runs "
                "using equivalent configs (all severities, fixed and unfixed). "
                "Disagreement is NOT a false-positive/false-negative rate; "
                "ground truth requires manual adjudication."
            ),
            "confirmed":        sorted(result.confirmed),
            "trivy_only":       sorted(result.trivy_only),
            "grype_only":       sorted(result.grype_only),
            "scanner_disagreement": {
                "trivy_only_rate": result.trivy_only_rate,
                "grype_only_rate": result.grype_only_rate,
            },
            # Backward-compatible aliases for older consumers.
            "fp_candidates":    sorted(result.fp_candidates),
            "fn_candidates":    sorted(result.fn_candidates),
            "fp_rate":          result.fp_rate,
            "fn_rate":          result.fn_rate,
        }, indent=2)
    )

    print(f"  Confirmed findings : {len(result.confirmed)}")
    print(f"  Trivy-only findings: {len(result.trivy_only)} ({result.trivy_only_rate}%)")
    print(f"  Grype-only findings: {len(result.grype_only)} ({result.grype_only_rate}%)")
    return result


if __name__ == "__main__":
    validate(Path(sys.argv[1]))

# analysis/disagreement_breakdown.py
# Breaks scanner disagreement down by package ecosystem — answers "WHERE do
# the scanners disagree?" rather than just "how much?"
# Usage: python3 -m analysis.disagreement_breakdown <results_dir>

from __future__ import annotations
from pathlib import Path
from collections import Counter
import json, sys

from analysis.parsers import parse_trivy


def breakdown(results_dir: Path) -> dict[str, Counter]:
    val = json.loads((results_dir / "validation.json").read_text())
    trivy_only = set(val.get("trivy_only", []))
    confirmed  = set(val.get("confirmed", []))

    by_id: dict[str, str] = {}
    for cve in parse_trivy(results_dir / "trivy.json"):
        by_id.setdefault(cve.id, cve.pkg_type)

    result = {
        "trivy_only_by_pkg_type": Counter(by_id.get(i, "unknown") for i in trivy_only),
        "confirmed_by_pkg_type":  Counter(by_id.get(i, "unknown") for i in confirmed),
    }

    for label, counter in result.items():
        print(f"\n{label}:")
        for pkg_type, n in counter.most_common():
            print(f"  {pkg_type:<12} {n}")
    return result


if __name__ == "__main__":
    breakdown(Path(sys.argv[1]))

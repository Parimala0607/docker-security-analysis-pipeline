# analysis/comparator.py
# Compares scan results across multiple images — produces the research table
# Usage: python3 -m analysis.comparator

from __future__ import annotations
from pathlib import Path
import json
from collections import Counter

from analysis.models import Severity


def _count_severities(enriched_path: Path) -> Counter:
    if not enriched_path.exists():
        return Counter()
    data = json.loads(enriched_path.read_text())
    return Counter(item["severity"] for item in data)


def _summarise(results_dir: Path) -> dict:
    enriched_path   = results_dir / "enriched.json"
    validation_path = results_dir / "validation.json"

    # A scan that didn't produce enriched output FAILED — it must never be
    # rendered as a clean image. Zeros and "no data" are different claims.
    if not enriched_path.exists() or not validation_path.exists():
        return {"status": "FAILED", "CRITICAL": None, "HIGH": None,
                "MEDIUM": None, "LOW": None, "in_kev": None,
                "confirmed": None, "trivy_only": None, "grype_only": None,
                "trivy_only_rate": None, "grype_only_rate": None}

    counts = _count_severities(enriched_path)
    val    = json.loads(validation_path.read_text())
    enriched = json.loads(enriched_path.read_text())

    return {
        "status":   "ok",
        "CRITICAL": counts.get(Severity.CRITICAL.value, 0),
        "HIGH":     counts.get(Severity.HIGH.value, 0),
        "MEDIUM":   counts.get(Severity.MEDIUM.value, 0),
        "LOW":      counts.get(Severity.LOW.value, 0),
        "in_kev":   sum(1 for i in enriched if i.get("in_kev")),
        # Raw counts alongside rates: a 100% rate on n=1 and on n=200 are
        # very different claims, so always show n.
        "confirmed":  len(val.get("confirmed", [])),
        "trivy_only": len(val.get("trivy_only", val.get("fp_candidates", []))),
        "grype_only": len(val.get("grype_only", val.get("fn_candidates", []))),
        "trivy_only_rate": val.get("scanner_disagreement", {}).get(
            "trivy_only_rate", val.get("fp_rate")),
        "grype_only_rate": val.get("scanner_disagreement", {}).get(
            "grype_only_rate", val.get("fn_rate")),
    }


def _fmt(value, width: int) -> str:
    return f"{('—' if value is None else value)!s:>{width}}"


def compare(results_root: Path = Path("results")) -> dict[str, dict]:
    """Aggregate latest scan per image from results directory."""
    latest: dict[str, Path] = {}
    for folder in sorted(results_root.iterdir()):
        if not folder.is_dir():
            continue
        # Folder name: 20250530_120000_nginx__1_21 → image key after first two _
        image_key = "_".join(folder.name.split("_")[2:])
        latest[image_key] = folder   # Later timestamps overwrite earlier

    comparison = {key: _summarise(path) for key, path in latest.items()}

    header = (
        f"{'Image':<40} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'KEV':>4} "
        f"{'Both':>5} {'T-only':>7} {'G-only':>7} {'T-only%':>8} {'G-only%':>8}  Status"
    )
    print("\n" + header)
    print("─" * len(header))
    for image, d in comparison.items():
        print(
            f"{image:<40} "
            f"{_fmt(d['CRITICAL'],5)} {_fmt(d['HIGH'],5)} {_fmt(d['MEDIUM'],5)} "
            f"{_fmt(d['LOW'],5)} {_fmt(d['in_kev'],4)} "
            f"{_fmt(d['confirmed'],5)} {_fmt(d['trivy_only'],7)} {_fmt(d['grype_only'],7)} "
            f"{_fmt(d['trivy_only_rate'],8)} {_fmt(d['grype_only_rate'],8)}  "
            f"{'⚠ ' + d['status'] if d['status'] != 'ok' else 'ok'}"
        )

    failed = [k for k, d in comparison.items() if d["status"] == "FAILED"]
    if failed:
        print(f"\n⚠  {len(failed)} scan(s) FAILED and are excluded from analysis: "
              + ", ".join(failed))

    (results_root / "comparison.json").write_text(json.dumps(comparison, indent=2))
    return comparison


if __name__ == "__main__":
    compare()

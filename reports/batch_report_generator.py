# reports/batch_report_generator.py
# Builds the aggregate HTML report expected by batch_scan.sh.
# Usage: python3 -m reports.batch_report_generator <results_dir> <timestamp>

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import json
import sys

from jinja2 import Environment, FileSystemLoader


def _load(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _image_key(folder: Path) -> str:
    return "_".join(folder.name.split("_")[2:])


def _rate(validation: dict, current: str, legacy: str) -> float | None:
    scanner_disagreement = validation.get("scanner_disagreement", {})
    value = scanner_disagreement.get(current, validation.get(legacy))
    return value if isinstance(value, (int, float)) else None


def _summarise_scan(folder: Path) -> dict | None:
    enriched = _load(folder / "enriched.json")
    validation = _load(folder / "validation.json")
    metadata = _load(folder / "metadata.json")

    if not isinstance(enriched, list) or not isinstance(validation, dict):
        return None

    counts = Counter(item.get("severity", "UNKNOWN") for item in enriched)
    return {
        "image": metadata.get("image") if isinstance(metadata, dict) else _image_key(folder),
        "result_dir": str(folder),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "kev": sum(1 for item in enriched if item.get("in_kev")),
        "trivy_only_rate": _rate(validation, "trivy_only_rate", "fp_rate"),
        "grype_only_rate": _rate(validation, "grype_only_rate", "fn_rate"),
        # Legacy template names; keep them so old templates still render.
        "fp_rate": _rate(validation, "trivy_only_rate", "fp_rate"),
        "fn_rate": _rate(validation, "grype_only_rate", "fn_rate"),
        "findings": len(enriched),
        "risk_weight": (
            counts.get("CRITICAL", 0) * 1000
            + counts.get("HIGH", 0) * 100
            + counts.get("MEDIUM", 0) * 10
            + counts.get("LOW", 0)
        ),
    }


def _top_findings(scan_dirs: list[Path], limit: int = 50) -> list[dict]:
    findings: list[dict] = []
    for folder in scan_dirs:
        enriched = _load(folder / "enriched.json")
        metadata = _load(folder / "metadata.json")
        if not isinstance(enriched, list):
            continue
        image = metadata.get("image", _image_key(folder)) if isinstance(metadata, dict) else _image_key(folder)
        for item in enriched:
            if isinstance(item, dict):
                findings.append({**item, "image": image})

    findings.sort(
        key=lambda item: (
            item.get("risk_score", 0),
            1 if item.get("in_kev") else 0,
            item.get("cvss", 0),
        ),
        reverse=True,
    )
    return findings[:limit]


def _avg(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def generate(results_dir: Path, timestamp: str) -> Path:
    scan_dirs = [folder for folder in sorted(results_dir.iterdir()) if folder.is_dir()]
    summaries = [item for folder in scan_dirs if (item := _summarise_scan(folder)) is not None]

    severity_totals = Counter()
    for item in summaries:
        severity_totals.update({
            "CRITICAL": item["critical"],
            "HIGH": item["high"],
            "MEDIUM": item["medium"],
            "LOW": item["low"],
        })

    trivy_rates = [item["trivy_only_rate"] for item in summaries if item["trivy_only_rate"] is not None]
    grype_rates = [item["grype_only_rate"] for item in summaries if item["grype_only_rate"] is not None]

    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"))
    template = env.get_template("batch_report.html.j2")
    html = template.render(
        generated_at=datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%d %b %Y %H:%M"),
        image_count=len(summaries),
        severity_totals=severity_totals,
        average_fp=_avg(trivy_rates),
        average_fn=_avg(grype_rates),
        average_trivy_only=_avg(trivy_rates),
        average_grype_only=_avg(grype_rates),
        worst_images=sorted(summaries, key=lambda item: item["risk_weight"], reverse=True),
        top_findings=_top_findings(scan_dirs),
    )

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"batch_report_{timestamp}.html"
    out_path.write_text(html)
    print(f"  Batch report saved -> {out_path}")
    return out_path


if __name__ == "__main__":
    generate(Path(sys.argv[1]), sys.argv[2])

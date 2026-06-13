# reports/report_generator.py
# Generates a self-contained HTML report from all scan results
# Usage: python3 -m reports.report_generator <image> <results_dir> <timestamp>

from __future__ import annotations
from pathlib import Path
import json, sys, base64
from collections import Counter
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

_TRANSPARENT_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Y5Z8AAAAASUVORK5CYII="
)

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _MATPLOTLIB_AVAILABLE = True
except Exception:
    plt = None
    _MATPLOTLIB_AVAILABLE = False


def _chart_b64(counts: dict[str, int]) -> str:
    """Generate severity bar chart and return as base64 PNG."""
    if not _MATPLOTLIB_AVAILABLE:
        return _TRANSPARENT_PNG_B64

    colours = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
    fig, ax = plt.subplots(figsize=(6, 3), facecolor="#ffffff")
    ax.set_facecolor("#ffffff")
    labels  = [k for k in colours if k in counts]
    values  = [counts[k] for k in labels]
    bars    = ax.bar(labels, values, color=[colours[k] for k in labels])
    ax.bar_label(bars, padding=3, color="#0f172a", fontsize=10)
    ax.set_title("CVEs by Severity", color="#0f172a", fontsize=12)
    ax.tick_params(colors="#334155")
    for spine in ax.spines.values():
        spine.set_edgecolor("#cbd5e1")
    buf = __import__("io").BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()


def _load(path: Path) -> dict | list:
    return json.loads(path.read_text()) if path.exists() else {}


def generate(image: str, results_dir: Path, timestamp: str) -> Path:
    enriched   = _load(results_dir / "enriched.json")
    validation = _load(results_dir / "validation.json")
    dockle     = _load(results_dir / "dockle.json")
    metadata   = _load(results_dir / "metadata.json")
    policy     = _load(results_dir / "policy.json")
    scanner_status = _load(results_dir / "scanner_status.json")

    counts = {sev: sum(1 for c in enriched if c["severity"] == sev)
              for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    priority_counts = {
        p: sum(1 for c in enriched if c.get("priority") == p)
        for p in ("P1-CRITICAL", "P2-HIGH", "P3-MONITOR")
    }
    vex_findings = [
        c for c in enriched
        if c.get("vex_status") not in (None, "", "unknown")
        or c.get("vex_reachability") not in (None, "", "unknown")
        or c.get("vex_justification")
        or c.get("vex_detail")
    ]
    vex_counts = Counter(c.get("vex_status", "unknown") for c in vex_findings)
    reachability_counts = Counter(c.get("vex_reachability", "unknown") for c in vex_findings)

    env      = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"))
    template = env.get_template("report.html.j2")

    html = template.render(
        image      = image,
        timestamp  = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%d %b %Y %H:%M"),
        cves       = enriched,
        validation = validation,
        dockle     = dockle,
        metadata   = metadata,
        policy     = policy,
        scanner_status = scanner_status,
        counts     = counts,
        priority_counts = priority_counts,
        vex_findings = vex_findings,
        vex_counts = vex_counts,
        reachability_counts = reachability_counts,
        chart_b64  = _chart_b64(counts),
    )

    out_dir  = Path("reports")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"report_{timestamp}.html"
    out_path.write_text(html)
    print(f"  Report saved → {out_path}")
    return out_path


if __name__ == "__main__":
    generate(sys.argv[1], Path(sys.argv[2]), sys.argv[3])

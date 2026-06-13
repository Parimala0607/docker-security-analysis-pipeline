# analysis/layer_attribution.py
# Coarsely classifies findings as likely base-image or application dependency issues.
# This is a heuristic, not exact Dockerfile-layer attribution.

from __future__ import annotations
from pathlib import Path
import json, sys

from analysis.parsers import parse_trivy


_OS_PKG_TYPES = {"apk", "deb", "rpm", "dpkg", "os", "binary"}
_APP_PKG_TYPES = {"npm", "pip", "pypi", "bundler", "composer", "maven", "go", "nuget", "cargo", "gem", "nodejs"}


def _origin_from_pkg_type(pkg_type: str) -> str:
    normalized = (pkg_type or "").lower()
    if normalized in _OS_PKG_TYPES:
        return "base_image"
    if normalized in _APP_PKG_TYPES:
        return "application_dependency"
    return "unknown"


def attribute(image: str, results_dir: Path) -> list[dict]:
    cves   = parse_trivy(results_dir / "trivy.json")
    print(f"  Classifying finding origin for {image}")

    attributed = []
    for cve in cves:
        origin = _origin_from_pkg_type(cve.pkg_type)
        attributed.append({
            "cve":      cve.id,
            "package":  cve.package,
            "severity": cve.severity.value,
            "pkg_type": cve.pkg_type,
            "origin":   origin,
            "source":   origin,  # Backward-compatible field name
        })

    (results_dir / "layers.json").write_text(json.dumps(attributed, indent=2))

    base = sum(1 for a in attributed if a["origin"] == "base_image")
    app  = sum(1 for a in attributed if a["origin"] == "application_dependency")
    unk  = len(attributed) - base - app
    print(f"  Base image findings        : {base}")
    print(f"  Application dependency fnd : {app}")
    print(f"  Unclassified findings      : {unk}")
    return attributed


if __name__ == "__main__":
    from pathlib import Path
    attribute(sys.argv[1], Path(sys.argv[2]))

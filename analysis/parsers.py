# analysis/parsers.py
# Parse raw JSON from each scanner into CVE dataclasses
# Each parser is independent — adding a new scanner = adding one function

from __future__ import annotations
from pathlib import Path
import json

from analysis.models import CVE, Severity


def _severity(raw: str) -> Severity:
    try:
        return Severity(raw.upper())
    except ValueError:
        return Severity.UNKNOWN


def parse_trivy(path: Path) -> list[CVE]:
    data = json.loads(path.read_text())
    return [
        CVE(
            id       = v["VulnerabilityID"],
            package  = v["PkgName"],
            severity = _severity(v.get("Severity", "")),
            cvss     = v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
            fixed_in = v.get("FixedVersion", "N/A"),
            layer    = r.get("Target", "unknown"),
            pkg_type = v.get("PkgType", "unknown"),
        )
        for r in data.get("Results", [])
        for v in r.get("Vulnerabilities") or []
    ]


def normalize_grype_id(match: dict) -> str:
    """Return a CVE id for a Grype match when one exists.

    Grype reports language-ecosystem findings under GHSA (or distro-advisory)
    ids, while Trivy reports the same finding under its CVE id. Comparing raw
    id strings across scanners therefore inflates "disagreement" with entries
    that are actually the same vulnerability. When the primary id is not a
    CVE, prefer the first CVE listed in relatedVulnerabilities; otherwise
    keep the primary id so nothing is silently dropped.
    """
    primary = match["vulnerability"]["id"]
    if primary.startswith("CVE-"):
        return primary
    for related in match.get("relatedVulnerabilities") or []:
        rid = related.get("id", "")
        if rid.startswith("CVE-"):
            return rid
    return primary


def parse_grype(path: Path) -> list[CVE]:
    data = json.loads(path.read_text())
    return [
        CVE(
            id       = normalize_grype_id(m),
            package  = m["artifact"]["name"],
            severity = _severity(m["vulnerability"].get("severity", "")),
            cvss     = next(
                (c.get("metrics", {}).get("baseScore", 0.0)
                 for c in m["vulnerability"].get("cvss", [])
                 if c.get("version", "").startswith("3")),
                0.0,
            ),
            fixed_in = next(iter(m["vulnerability"].get("fix", {}).get("versions", [])), "N/A"),
            pkg_type = m.get("artifact", {}).get("type", "unknown"),
        )
        for m in data.get("matches", [])
    ]


def ids_from_trivy(path: Path) -> set[str]:
    return {c.id for c in parse_trivy(path)}


def ids_from_grype(path: Path) -> set[str]:
    return {c.id for c in parse_grype(path)}

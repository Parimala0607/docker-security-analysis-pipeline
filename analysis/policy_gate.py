# analysis/policy_gate.py
# Writes a small risk-policy result for reports and optional CI enforcement.
# Usage: python3 -m analysis.policy_gate <results_dir>

from __future__ import annotations

from pathlib import Path
import json
import os
import sys


EPSS_CRITICAL_THRESHOLD = float(os.environ.get("POLICY_EPSS_CRITICAL_THRESHOLD", "0.2"))
EPSS_ANY_THRESHOLD = float(os.environ.get("POLICY_EPSS_ANY_THRESHOLD", "0.7"))


def _load(path: Path) -> list[dict]:
    return json.loads(path.read_text()) if path.exists() else []


def _violates_policy(item: dict) -> bool:
    epss = float(item.get("epss") or 0.0)
    severity = item.get("severity")
    return bool(
        item.get("in_kev")
        or epss >= EPSS_ANY_THRESHOLD
        or (severity == "CRITICAL" and epss >= EPSS_CRITICAL_THRESHOLD)
    )


def evaluate(results_dir: Path) -> dict:
    enriched = _load(results_dir / "enriched.json")
    violations = [
        {
            "id": item.get("id"),
            "package": item.get("package"),
            "severity": item.get("severity"),
            "epss": item.get("epss", 0.0),
            "in_kev": item.get("in_kev", False),
            "priority": item.get("priority"),
            "risk_score": item.get("risk_score"),
        }
        for item in enriched
        if _violates_policy(item)
    ]

    result = {
        "status": "fail" if violations else "pass",
        "enforced": os.environ.get("POLICY_ENFORCE") == "1",
        "criteria": {
            "in_kev": True,
            "epss_any_threshold": EPSS_ANY_THRESHOLD,
            "critical_epss_threshold": EPSS_CRITICAL_THRESHOLD,
        },
        "violation_count": len(violations),
        "violations": violations,
    }

    (results_dir / "policy.json").write_text(json.dumps(result, indent=2))
    print(f"  Policy status: {result['status']} ({len(violations)} prioritized finding(s))")
    if result["status"] == "fail" and result["enforced"]:
        raise SystemExit(1)
    return result


if __name__ == "__main__":
    evaluate(Path(sys.argv[1]))

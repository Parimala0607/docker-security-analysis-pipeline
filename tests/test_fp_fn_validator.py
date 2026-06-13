# tests/test_fp_fn_validator.py

import json

from analysis.models import ValidationResult


def test_fp_rate_calculation():
    r = ValidationResult(
        confirmed  = {"CVE-A", "CVE-B"},
        trivy_only = {"CVE-C"},
        grype_only = set(),
    )
    assert r.fp_rate == 33.33   # 1 FP out of 3 total
    assert r.trivy_only_rate == 33.33


def test_fn_rate_calculation():
    r = ValidationResult(
        confirmed  = {"CVE-A"},
        trivy_only = set(),
        grype_only = {"CVE-B", "CVE-C"},
    )
    assert r.fn_rate == 66.67   # 2 FN out of 3 total
    assert r.grype_only_rate == 66.67


def test_all_confirmed_zero_rates():
    r = ValidationResult(confirmed={"CVE-A", "CVE-B"})
    assert r.fp_rate == 0.0
    assert r.fn_rate == 0.0


def test_grype_ghsa_ids_normalize_to_cve(tmp_path):
    from analysis.parsers import ids_from_grype
    grype = {
        "matches": [
            {"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "severity": "High"},
             "relatedVulnerabilities": [{"id": "CVE-2024-1234"}],
             "artifact": {"name": "lodash", "type": "npm"}},
            {"vulnerability": {"id": "CVE-2023-44487", "severity": "High"},
             "relatedVulnerabilities": [],
             "artifact": {"name": "libnghttp2", "type": "deb"}},
            {"vulnerability": {"id": "GHSA-orphan-no-cve", "severity": "Low"},
             "artifact": {"name": "leftpad", "type": "npm"}},
        ]
    }
    p = tmp_path / "grype.json"
    p.write_text(json.dumps(grype))
    ids = ids_from_grype(p)
    assert ids == {"CVE-2024-1234", "CVE-2023-44487", "GHSA-orphan-no-cve"}

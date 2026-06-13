import json

from analysis.models import CVE, Severity, Priority, VexStatus
from analysis.vex import load_vex_records
from reports.report_generator import generate


def test_load_cyclonedx_vex_records(tmp_path, monkeypatch):
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    (vex_dir / "sample.cdx.json").write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-44228",
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_reachable",
                            "detail": "Mitigating control blocks the attack path.",
                        },
                    }
                ]
            }
        )
    )
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    monkeypatch.setenv("VEX_PATHS", str(vex_dir))

    records = load_vex_records(results_dir)
    record = records["CVE-2021-44228"]

    assert record.status == VexStatus.NOT_AFFECTED
    assert record.justification == "code_not_reachable"
    assert record.reachability.value == "not_reachable"


def test_not_affected_vex_downgrades_priority():
    cve = CVE(
        id="CVE-2021-44228",
        package="log4j",
        severity=Severity.CRITICAL,
        cvss=10.0,
        epss=0.97,
        in_kev=True,
        vex_status=VexStatus.NOT_AFFECTED.value,
    )

    assert cve.priority == Priority.P3


def test_report_only_shows_vex_section_for_real_vex_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    (results_dir / "enriched.json").write_text(
        json.dumps(
            [
                {
                    "id": "CVE-1",
                    "package": "pkg",
                    "severity": "HIGH",
                    "cvss": 8.1,
                    "epss": 0.2,
                    "in_kev": False,
                    "vex_status": "not_affected",
                    "vex_reachability": "not_reachable",
                    "vex_justification": "code_not_reachable",
                    "vex_detail": "The affected code path is not invoked.",
                    "vex_source": "vex/sample.cdx.json",
                    "risk_score": 0.8,
                    "priority": "P2-HIGH",
                    "fixed_in": "1.2.3",
                }
            ]
        )
    )
    (results_dir / "validation.json").write_text(json.dumps({"confirmed": [], "fp_rate": 0, "fn_rate": 0}))
    (results_dir / "dockle.json").write_text(json.dumps({}))
    (results_dir / "metadata.json").write_text(json.dumps({}))

    out = generate("img:1", results_dir, "20260606_000000")
    html = out.read_text()

    assert "VEX / Reachability Evidence" in html
    assert "code_not_reachable" in html
    assert "vex/sample.cdx.json" in html


def test_report_hides_vex_section_without_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    (results_dir / "enriched.json").write_text(
        json.dumps(
            [
                {
                    "id": "CVE-1",
                    "package": "pkg",
                    "severity": "HIGH",
                    "cvss": 8.1,
                    "epss": 0.2,
                    "in_kev": False,
                    "vex_status": "unknown",
                    "vex_reachability": "unknown",
                    "risk_score": 0.8,
                    "priority": "P2-HIGH",
                    "fixed_in": "1.2.3",
                }
            ]
        )
    )
    (results_dir / "validation.json").write_text(json.dumps({"confirmed": [], "fp_rate": 0, "fn_rate": 0}))
    (results_dir / "dockle.json").write_text(json.dumps({}))
    (results_dir / "metadata.json").write_text(json.dumps({}))

    out = generate("img:1", results_dir, "20260606_000000")
    html = out.read_text()

    assert "VEX / Reachability Evidence" not in html

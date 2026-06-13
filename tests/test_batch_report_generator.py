import json

from reports.batch_report_generator import generate


def test_batch_report_generator_renders_latest_scan_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    results = tmp_path / "results"
    scan = results / "20260613_120000_nginx_1_27"
    scan.mkdir(parents=True)
    (scan / "metadata.json").write_text(json.dumps({"image": "nginx:1.27"}))
    (scan / "validation.json").write_text(json.dumps({
        "scanner_disagreement": {
            "trivy_only_rate": 4.2,
            "grype_only_rate": 1.1,
        },
    }))
    (scan / "enriched.json").write_text(json.dumps([
        {
            "id": "CVE-2026-0001",
            "package": "openssl",
            "severity": "HIGH",
            "epss": 0.12,
            "in_kev": False,
            "priority": "P2-HIGH",
            "risk_score": 0.8,
            "fixed_in": "1.2.3",
        },
    ]))

    out_path = generate(results, "20260613_120000")

    html = out_path.read_text()
    assert "nginx:1.27" in html
    assert "CVE-2026-0001" in html
    assert "Avg Trivy-only: 4.2%" in html

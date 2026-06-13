import json

from analysis.scanner_status import collect


def test_collect_scanner_status_writes_summary(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "trivy.log").write_text("ok")
    (log_dir / "trivy.status").write_text("ok")
    (log_dir / "grype.log").write_text("failed")
    (log_dir / "grype.status").write_text("failed")

    result = collect(tmp_path)

    assert result["trivy"]["status"] == "ok"
    assert result["grype"]["status"] == "failed"
    assert result["dockle"]["status"] == "missing"
    assert json.loads((tmp_path / "scanner_status.json").read_text())["syft"]["status"] == "missing"

import json
from pathlib import Path

from analysis.scan_metadata import write


def test_write_metadata_includes_image_digest_and_versions(tmp_path, monkeypatch):
    calls = []

    def fake_check_output(cmd, text=True, stderr=None):
        calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return '["repo/image@sha256:abc123"]'
        if cmd[0] == "trivy":
            return "Trivy 0.1.0\n"
        if cmd[0] == "grype":
            return "Grype 0.2.0\n"
        if cmd[0] == "dockle":
            return "Dockle 0.3.0\n"
        if cmd[0] == "syft":
            return "Syft 0.4.0\n"
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr("analysis.scan_metadata.subprocess.check_output", fake_check_output)

    results_dir = tmp_path / "results"
    results_dir.mkdir()
    out_path = write("repo/image:1.0", results_dir)

    data = json.loads(out_path.read_text())
    assert data["image"] == "repo/image:1.0"
    assert data["image_digest"] == "repo/image@sha256:abc123"
    assert data["tool_versions"]["trivy"] == "Trivy 0.1.0"
    assert data["tool_versions"]["grype"] == "Grype 0.2.0"
    assert data["tool_versions"]["dockle"] == "Dockle 0.3.0"
    assert data["tool_versions"]["syft"] == "Syft 0.4.0"
    assert data["tool_details"]["trivy"] == "Trivy 0.1.0"
    assert data["scanner_database"]["grype"] == "Grype 0.2.0"
    assert calls

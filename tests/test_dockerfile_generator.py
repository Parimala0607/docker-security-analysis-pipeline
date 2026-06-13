from pathlib import Path
import json

from remediation.dockerfile_generator import generate


def test_generate_preserves_full_image_reference(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "enriched.json").write_text(
        json.dumps([{"severity": "CRITICAL"}, {"severity": "HIGH"}])
    )

    out_path = generate("ghcr.io/example/app:1.2.3", results_dir)
    content = out_path.read_text()

    assert out_path == Path("remediated") / "Dockerfile.app"
    assert "FROM ghcr.io/example/app:1.2.3" in content
    assert "FROM app:" not in content
    assert "command -v apk" in content
    assert "command -v apt-get" in content
    assert "Original : ghcr.io/example/app:1.2.3" in content


def test_generate_is_distro_aware_for_debian(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "trivy.json").write_text(
        json.dumps({"Metadata": {"OS": {"Family": "debian", "Name": "12.11"}}, "Results": []})
    )
    (results_dir / "metadata.json").write_text(
        json.dumps({"image_digest": "nginx@sha256:deadbeef"})
    )
    (results_dir / "enriched.json").write_text(
        json.dumps([
            {"id": "CVE-1", "package": "libfoo", "severity": "CRITICAL",
             "fixed_in": "1.2.3", "risk_score": 1.0},
        ])
    )

    content = generate("nginx:1.27", results_dir).read_text()

    assert "groupadd --system" in content          # Debian syntax, not BusyBox
    assert "addgroup -S" not in content
    assert "FROM nginx@sha256:deadbeef" in content  # digest-pinned
    assert "CVE-1" in content                       # data-driven summary
    assert "# USER appuser" in content              # USER off by default


def test_generate_is_distro_aware_for_alpine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "trivy.json").write_text(
        json.dumps({"Metadata": {"OS": {"Family": "alpine"}}, "Results": []})
    )

    content = generate("alpine:3.20", results_dir).read_text()
    assert "addgroup -S appgroup && adduser -S appuser" in content
    assert "groupadd" not in content

import json
from pathlib import Path
from analysis.comparator import compare

def make_scan(root, name, ok=True):
    d = root / f"20260612_120000_{name}"
    d.mkdir(parents=True)
    if ok:
        (d / "enriched.json").write_text(json.dumps(
            [{"severity": "CRITICAL", "in_kev": True},
             {"severity": "HIGH", "in_kev": False}]))
        (d / "validation.json").write_text(json.dumps({
            "confirmed": ["CVE-1"], "trivy_only": ["CVE-2"], "grype_only": [],
            "scanner_disagreement": {"trivy_only_rate": 50.0, "grype_only_rate": 0.0}}))

def test_failed_scan_not_rendered_as_clean(tmp_path):
    make_scan(tmp_path, "goodimage_1", ok=True)
    make_scan(tmp_path, "deadimage_1", ok=False)
    result = compare(tmp_path)
    assert result["goodimage_1"]["status"] == "ok"
    assert result["goodimage_1"]["CRITICAL"] == 1
    assert result["goodimage_1"]["in_kev"] == 1
    assert result["goodimage_1"]["confirmed"] == 1
    assert result["deadimage_1"]["status"] == "FAILED"
    assert result["deadimage_1"]["CRITICAL"] is None   # never zero

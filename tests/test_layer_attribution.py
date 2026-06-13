import json

from analysis.layer_attribution import attribute


def test_attribute_uses_package_type_heuristic(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "trivy.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.19",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-1",
                                "PkgName": "openssl",
                                "Severity": "HIGH",
                                "PkgType": "apk",
                            },
                            {
                                "VulnerabilityID": "CVE-2",
                                "PkgName": "requests",
                                "Severity": "LOW",
                                "PkgType": "pypi",
                            },
                        ],
                    }
                ]
            }
        )
    )

    findings = attribute("alpine:3.19", results_dir)
    assert findings[0]["origin"] == "base_image"
    assert findings[1]["origin"] == "application_dependency"

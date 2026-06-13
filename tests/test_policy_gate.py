import json

from analysis.policy_gate import evaluate


def test_policy_gate_flags_prioritized_runtime_risk(tmp_path, monkeypatch):
    monkeypatch.delenv("POLICY_ENFORCE", raising=False)
    (tmp_path / "enriched.json").write_text(json.dumps([
        {
            "id": "CVE-1",
            "package": "openssl",
            "severity": "CRITICAL",
            "epss": 0.01,
            "in_kev": False,
            "priority": "P1-CRITICAL",
            "risk_score": 1.0,
        },
        {
            "id": "CVE-2",
            "package": "glibc",
            "severity": "HIGH",
            "epss": 0.9,
            "in_kev": False,
            "priority": "P1-CRITICAL",
            "risk_score": 0.9,
        },
    ]))

    result = evaluate(tmp_path)

    assert result["status"] == "fail"
    assert result["violation_count"] == 1
    assert result["violations"][0]["id"] == "CVE-2"
    assert (tmp_path / "policy.json").exists()


def test_policy_gate_passes_raw_critical_without_exploitability_signal(tmp_path, monkeypatch):
    monkeypatch.delenv("POLICY_ENFORCE", raising=False)
    (tmp_path / "enriched.json").write_text(json.dumps([
        {
            "id": "CVE-1",
            "package": "openssl",
            "severity": "CRITICAL",
            "epss": 0.01,
            "in_kev": False,
            "priority": "P1-CRITICAL",
        },
    ]))

    assert evaluate(tmp_path)["status"] == "pass"

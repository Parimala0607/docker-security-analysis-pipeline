# tests/test_models.py

import pytest
from analysis.models import CVE, Severity, Priority


def make_cve(**kwargs) -> CVE:
    defaults = dict(id="CVE-2021-44228", package="log4j", severity=Severity.CRITICAL, cvss=10.0)
    return CVE(**{**defaults, **kwargs})


def test_risk_score_no_epss():
    cve = make_cve(epss=0.0)
    assert cve.severity_score == 1.0
    assert cve.risk_score == 1.0


def test_risk_score_with_epss():
    cve = make_cve(cvss=10.0, epss=0.97)
    assert cve.exploitability_score == 0.97
    assert cve.risk_score == 1.0


def test_kev_doubles_risk_score():
    base = make_cve(cvss=10.0, epss=0.5, in_kev=False)
    kev  = make_cve(cvss=10.0, epss=0.5, in_kev=True)
    assert base.exploitability_score == 0.5
    assert kev.exploitability_score == 1.0
    assert kev.risk_score == 1.0


def test_priority_p1_if_in_kev():
    cve = make_cve(epss=0.01, in_kev=True)  # Low EPSS but in KEV
    assert cve.priority == Priority.P1


def test_priority_p1_for_critical_severity():
    cve = make_cve(cvss=10.0, epss=0.0)
    assert cve.priority == Priority.P1


def test_priority_p3_low_risk():
    cve = make_cve(severity=Severity.LOW, cvss=3.0, epss=0.001, in_kev=False)
    assert cve.priority == Priority.P3

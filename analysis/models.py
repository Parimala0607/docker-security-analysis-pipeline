# analysis/models.py
# Shared data models — single source of truth for the whole pipeline

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    UNKNOWN  = "UNKNOWN"


class Priority(str, Enum):
    P1 = "P1-CRITICAL"   # Critical severity, KEV, or very high exploitability
    P2 = "P2-HIGH"       # High severity or elevated exploitability
    P3 = "P3-MONITOR"    # Lower priority / monitor and schedule


class VexStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    UNKNOWN = "unknown"


@dataclass
class CVE:
    id:       str
    package:  str
    severity: Severity
    cvss:     float
    fixed_in: str = "N/A"
    layer:    str = "unknown"
    pkg_type: str = "unknown"

    # Enriched fields — populated by epss_scorer.py
    epss:   float = 0.0
    in_kev: bool  = False
    vex_status: str = VexStatus.UNKNOWN.value
    vex_justification: str = ""
    vex_detail: str = ""
    vex_source: str = ""
    vex_reachability: str = "unknown"

    @property
    def severity_score(self) -> float:
        weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH:     0.8,
            Severity.MEDIUM:   0.5,
            Severity.LOW:      0.2,
            Severity.UNKNOWN:   0.1,
        }
        return weights.get(self.severity, 0.1)

    @property
    def exploitability_score(self) -> float:
        multiplier = 2.0 if self.in_kev else 1.0
        return round(min(1.0, self.epss * multiplier), 4)

    @property
    def risk_score(self) -> float:
        # Blend severity and exploitability rather than multiplying them away.
        return round(max(self.severity_score, self.exploitability_score), 4)

    @property
    def priority(self) -> Priority:
        if self.vex_status in {
            VexStatus.NOT_AFFECTED.value,
            VexStatus.FALSE_POSITIVE.value,
            VexStatus.FIXED.value,
        }:
            return Priority.P3
        if self.in_kev or self.severity == Severity.CRITICAL or self.exploitability_score >= 0.7:
            return Priority.P1
        if self.severity == Severity.HIGH or self.exploitability_score >= 0.2:
            return Priority.P2
        return Priority.P3


@dataclass(init=False)
class ValidationResult:
    confirmed:   set[str] = field(default_factory=set)
    trivy_only:  set[str] = field(default_factory=set)
    grype_only:  set[str] = field(default_factory=set)

    def __init__(
        self,
        confirmed: set[str] | None = None,
        trivy_only: set[str] | None = None,
        grype_only: set[str] | None = None,
        fp_candidates: set[str] | None = None,
        fn_candidates: set[str] | None = None,
    ) -> None:
        self.confirmed = set(confirmed or set())
        self.trivy_only = set(trivy_only if trivy_only is not None else (fp_candidates or set()))
        self.grype_only = set(grype_only if grype_only is not None else (fn_candidates or set()))

    @property
    def fp_candidates(self) -> set[str]:
        return self.trivy_only

    @property
    def fn_candidates(self) -> set[str]:
        return self.grype_only

    @property
    def trivy_only_rate(self) -> float:
        total = len(self.confirmed) + len(self.trivy_only)
        return round(len(self.trivy_only) / total * 100, 2) if total else 0.0

    @property
    def grype_only_rate(self) -> float:
        total = len(self.confirmed) + len(self.grype_only)
        return round(len(self.grype_only) / total * 100, 2) if total else 0.0

    @property
    def fp_rate(self) -> float:
        return self.trivy_only_rate

    @property
    def fn_rate(self) -> float:
        return self.grype_only_rate

# analysis/epss_scorer.py
# Enriches CVEs with EPSS exploit probability + CISA KEV status
# Usage: python3 -m analysis.epss_scorer <results_dir>

from __future__ import annotations
from pathlib import Path
import json
import sys
import logging
import time
import requests

from analysis.models import CVE
from analysis.parsers import parse_trivy
from analysis.vex import Reachability, load_vex_records

log = logging.getLogger(__name__)
_KEV_CACHE: set[str] | None = None  # Module-level cache — KEV loaded once per run

KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _load_kev() -> set[str]:
    global _KEV_CACHE
    if _KEV_CACHE is None:
        try:
            r = requests.get(KEV_URL, timeout=10)
            r.raise_for_status()
            _KEV_CACHE = {v["cveID"] for v in r.json()["vulnerabilities"]}
            log.info(f"Loaded {len(_KEV_CACHE)} KEV entries")
        except Exception as e:
            log.warning(f"KEV feed unavailable; continuing without KEV matches: {e}")
            _KEV_CACHE = set()
    return _KEV_CACHE


def _fetch_epss_batch(cve_ids: list[str], chunk_size: int = 100) -> dict[str, float]:
    """Fetch EPSS scores in batches of `chunk_size`.

    FIRST's EPSS API accepts comma-separated CVE lists, so a 5,000-CVE image
    needs ~50 requests instead of 5,000. If a chunk fails after retries, fall
    back to per-CVE fetches for that chunk only, so one bad id can't zero out
    99 good ones.
    """
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    unique = sorted(set(cve_ids))

    for start in range(0, len(unique), chunk_size):
        chunk = unique[start:start + chunk_size]
        for attempt in range(3):
            try:
                r = requests.get(
                    EPSS_URL,
                    params={"cve": ",".join(chunk)},
                    timeout=30,
                )
                r.raise_for_status()
                for row in r.json().get("data", []):
                    scores[row["cve"]] = float(row["epss"])
                break
            except Exception as e:
                wait = 2 ** attempt
                log.warning(f"EPSS batch attempt {attempt + 1} failed "
                            f"({len(chunk)} CVEs): {e}")
                time.sleep(wait)
        else:
            # Chunk failed all retries — try its members individually.
            scores.update(_fetch_epss_single(chunk))
        time.sleep(0.1)   # be polite to the API between chunks
    return scores


def _fetch_epss_single(cve_ids: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for cve_id in cve_ids:
        try:
            r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=15)
            r.raise_for_status()
            data = r.json().get("data", [])
            if data:
                scores[cve_id] = float(data[0]["epss"])
        except Exception as e:
            log.warning(f"EPSS single fetch failed for {cve_id}: {e}")
        time.sleep(0.1)
    return scores


def enrich(cves: list[CVE], results_dir: Path) -> list[CVE]:
    """Add EPSS + KEV data to each CVE. Returns sorted by risk_score desc."""
    kev    = _load_kev()
    scores = _fetch_epss_batch([c.id for c in cves])
    vex_map = load_vex_records(results_dir)

    for cve in cves:
        cve.epss   = scores.get(cve.id, 0.0)
        cve.in_kev = cve.id in kev
        vex = vex_map.get(cve.id)
        if vex:
            cve.vex_status = vex.status.value
            cve.vex_justification = vex.justification
            cve.vex_detail = vex.detail
            cve.vex_source = vex.source
            cve.vex_reachability = vex.reachability.value
        else:
            cve.vex_status = "unknown"
            cve.vex_justification = ""
            cve.vex_detail = ""
            cve.vex_source = ""
            cve.vex_reachability = Reachability.UNKNOWN.value

    return sorted(cves, key=lambda c: c.risk_score, reverse=True)


def run(results_dir: Path) -> list[CVE]:
    cves     = parse_trivy(results_dir / "trivy.json")
    enriched = enrich(cves, results_dir)

    (results_dir / "enriched.json").write_text(
        json.dumps([
            {
                "id":         c.id,
                "package":    c.package,
                "severity":   c.severity.value,
                "cvss":       c.cvss,
                "severity_score": c.severity_score,
                "exploitability_score": c.exploitability_score,
                "epss":       c.epss,
                "in_kev":     c.in_kev,
                "vex_status": c.vex_status,
                "vex_reachability": c.vex_reachability,
                "vex_justification": c.vex_justification,
                "vex_detail": c.vex_detail,
                "vex_source": c.vex_source,
                "risk_score": c.risk_score,
                "priority":   c.priority.value,
                "fixed_in":   c.fixed_in,
            }
            for c in enriched
        ], indent=2)
    )

    p1 = sum(1 for c in enriched if c.priority.value == "P1-CRITICAL")
    print(f"  Total CVEs    : {len(enriched)}")
    print(f"  In CISA KEV   : {sum(c.in_kev for c in enriched)}")
    print(f"  VEX records   : {sum(1 for c in enriched if c.vex_status != 'unknown')}")
    print(f"  P1 (act now)  : {p1}")
    return enriched


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    run(Path(sys.argv[1]))

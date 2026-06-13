# analysis/vex.py
# Loads VEX / reachability statements from local advisory files.

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import json
import os

from analysis.models import VexStatus


class Reachability(str, Enum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VEXRecord:
    cve_id: str
    status: VexStatus = VexStatus.UNKNOWN
    justification: str = ""
    detail: str = ""
    source: str = ""
    reachability: Reachability = Reachability.UNKNOWN


_CYCLONEDX_STATE_MAP = {
    "affected": VexStatus.AFFECTED,
    "exploitable": VexStatus.EXPLOITABLE,
    "not_affected": VexStatus.NOT_AFFECTED,
    "in_triage": VexStatus.IN_TRIAGE,
    "false_positive": VexStatus.FALSE_POSITIVE,
    "resolved": VexStatus.FIXED,
    "resolved_with_pedigree": VexStatus.FIXED,
}

_CSAF_STATUS_PRIORITY = (
    ("known_affected", VexStatus.AFFECTED),
    ("under_investigation", VexStatus.IN_TRIAGE),
    ("known_not_affected", VexStatus.NOT_AFFECTED),
    ("fixed", VexStatus.FIXED),
)

_VEX_STATUS_SCORE = {
    VexStatus.EXPLOITABLE: 5,
    VexStatus.AFFECTED: 4,
    VexStatus.IN_TRIAGE: 3,
    VexStatus.NOT_AFFECTED: 2,
    VexStatus.FIXED: 2,
    VexStatus.FALSE_POSITIVE: 2,
    VexStatus.UNKNOWN: 1,
}


def _normalize_status(raw: str | None) -> VexStatus:
    if not raw:
        return VexStatus.UNKNOWN
    return _CYCLONEDX_STATE_MAP.get(raw.strip().lower(), VexStatus.UNKNOWN)


def _reachability_for(status: VexStatus) -> Reachability:
    if status in {VexStatus.AFFECTED, VexStatus.EXPLOITABLE, VexStatus.IN_TRIAGE}:
        return Reachability.REACHABLE
    if status in {VexStatus.NOT_AFFECTED, VexStatus.FALSE_POSITIVE, VexStatus.FIXED}:
        return Reachability.NOT_REACHABLE
    return Reachability.UNKNOWN


def _status_rank(status: VexStatus) -> int:
    return _VEX_STATUS_SCORE.get(status, 1)


def _pick_more_conservative(left: VEXRecord, right: VEXRecord) -> VEXRecord:
    if _status_rank(right.status) > _status_rank(left.status):
        return right
    if _status_rank(right.status) < _status_rank(left.status):
        return left

    # Prefer the record with more detail and a more specific source label.
    if len(right.detail) > len(left.detail):
        return right
    if len(right.detail) < len(left.detail):
        return left
    return right if right.source and not left.source else left


def _record(cve_id: str, status: VexStatus, justification: str, detail: str, source: str) -> VEXRecord:
    return VEXRecord(
        cve_id=cve_id,
        status=status,
        justification=justification or "",
        detail=detail or "",
        source=source,
        reachability=_reachability_for(status),
    )


def _parse_cyclonedx(data: dict, source: str) -> list[VEXRecord]:
    records: list[VEXRecord] = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("id") or vuln.get("cve")
        if not cve_id:
            continue
        analysis = vuln.get("analysis") or {}
        status = _normalize_status(analysis.get("state"))
        records.append(
            _record(
                cve_id=cve_id,
                status=status,
                justification=str(analysis.get("justification", "") or ""),
                detail=str(analysis.get("detail", "") or ""),
                source=source,
            )
        )
    return records


def _parse_csaf(data: dict, source: str) -> list[VEXRecord]:
    records: list[VEXRecord] = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cve") or vuln.get("title")
        if not cve_id or not str(cve_id).startswith("CVE-"):
            continue

        product_status = vuln.get("product_status") or {}
        status = VexStatus.UNKNOWN
        for key, mapped in _CSAF_STATUS_PRIORITY:
            if product_status.get(key):
                status = mapped
                break

        notes = vuln.get("notes") or []
        note_text = " ".join(
            note.get("text", "") for note in notes if isinstance(note, dict)
        ).strip()

        records.append(
            _record(
                cve_id=str(cve_id),
                status=status,
                justification=note_text,
                detail=note_text,
                source=source,
            )
        )
    return records


def _parse_generic(data: object, source: str) -> list[VEXRecord]:
    records: list[VEXRecord] = []
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        if "vulnerabilities" in data:
            entries = data["vulnerabilities"]
        else:
            entries = [data]
    else:
        entries = []

    for item in entries:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cve_id") or item.get("cve") or item.get("id")
        if not cve_id or not str(cve_id).startswith("CVE-"):
            continue
        status = _normalize_status(
            item.get("status") or item.get("analysis_state") or item.get("state")
        )
        records.append(
            _record(
                cve_id=str(cve_id),
                status=status,
                justification=str(item.get("justification", "") or ""),
                detail=str(item.get("detail", "") or item.get("reason", "") or ""),
                source=source,
            )
        )
    return records


def _load_file(path: Path) -> list[VEXRecord]:
    data = json.loads(path.read_text())
    source = str(path)

    if isinstance(data, dict) and "vulnerabilities" in data and any(
        isinstance(v, dict) and "analysis" in v for v in data.get("vulnerabilities", [])
    ):
        return _parse_cyclonedx(data, source)

    if isinstance(data, dict) and ("document" in data or "product_tree" in data):
        return _parse_csaf(data, source)

    return _parse_generic(data, source)


def discover_vex_files(results_dir: Path) -> list[Path]:
    roots: list[Path] = []
    env_paths = os.environ.get("VEX_PATHS", "")
    if env_paths:
        roots.extend(Path(p).expanduser() for p in env_paths.split(os.pathsep) if p)

    roots.extend(
        [
            Path("config/vex"),
            Path("vex"),
            results_dir / "vex",
            results_dir / "vex.json",
        ]
    )

    files: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = [
                *sorted(root.glob("*.json")),
                *sorted(root.glob("*.cdx.json")),
                *sorted(root.glob("*.csaf.json")),
            ]
        else:
            candidates = []

        for candidate in candidates:
            if candidate.exists():
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    files.append(candidate)
    return files


def load_vex_records(results_dir: Path) -> dict[str, VEXRecord]:
    records: dict[str, VEXRecord] = {}
    for path in discover_vex_files(results_dir):
        for record in _load_file(path):
            current = records.get(record.cve_id)
            if current is None:
                records[record.cve_id] = record
            else:
                records[record.cve_id] = _pick_more_conservative(current, record)
    return records

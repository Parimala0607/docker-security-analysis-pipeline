# analysis/scan_metadata.py
# Captures provenance data for a scan so the final report can show what was scanned.

from __future__ import annotations
from pathlib import Path
import json, subprocess, sys
from datetime import datetime, timezone


def _cmd_version(cmd: str) -> str:
    out = _cmd_output([cmd, "--version"])
    return out.splitlines()[0].strip() if out != "unavailable" else out


def _cmd_output(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()
    except Exception:
        return "unavailable"


def _image_digest(image: str) -> str:
    try:
        out = subprocess.check_output(
            ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        digests = json.loads(out) if out else []
        return digests[0] if digests else "unavailable"
    except Exception:
        return "unavailable"


def write(image: str, results_dir: Path) -> Path:
    metadata = {
        "image": image,
        "image_digest": _image_digest(image),
        "scan_started_at": datetime.now(timezone.utc).isoformat(),
        "tool_versions": {
            "trivy": _cmd_version("trivy"),
            "grype": _cmd_version("grype"),
            "dockle": _cmd_version("dockle"),
            "syft": _cmd_version("syft"),
        },
        "tool_details": {
            "trivy": _cmd_output(["trivy", "--version"]),
            "grype": _cmd_output(["grype", "--version"]),
            "dockle": _cmd_output(["dockle", "--version"]),
            "syft": _cmd_output(["syft", "--version"]),
        },
        "scanner_database": {
            "trivy": _cmd_output(["trivy", "--version"]),
            "grype": _cmd_output(["grype", "db", "status"]),
        },
    }

    out_path = results_dir / "metadata.json"
    out_path.write_text(json.dumps(metadata, indent=2))
    return out_path


if __name__ == "__main__":
    write(sys.argv[1], Path(sys.argv[2]))

# remediation/dockerfile_generator.py
# Generates a remediation-starting-point Dockerfile for the scanned image.
# It is distro-aware (via Trivy's OS metadata), digest-pinned (via scan
# metadata), and summarises the fixable findings it is responding to.
# Usage: python3 -m remediation.dockerfile_generator <image> <results_dir>

from __future__ import annotations
from pathlib import Path
import json, sys

# Map Trivy's Metadata.OS.Family to the correct non-root user commands.
# Emitting Alpine's `adduser -S` on a Debian image fails the build, so the
# distro decides the syntax instead of guessing.
_USER_COMMANDS: dict[str, str] = {
    "alpine": "RUN addgroup -S appgroup && adduser -S appuser -G appgroup",
    "debian": "RUN groupadd --system appgroup && useradd --system --gid appgroup --no-create-home appuser",
    "ubuntu": "RUN groupadd --system appgroup && useradd --system --gid appgroup --no-create-home appuser",
}

_PKG_UPGRADE: dict[str, str] = {
    "alpine": "RUN apk update && apk upgrade --no-cache",
    "debian": "RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*",
    "ubuntu": "RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*",
}

_FALLBACK_UPGRADE = """\
RUN set -eux; \\
    if command -v apk >/dev/null 2>&1; then \\
        apk update && apk upgrade --no-cache && rm -rf /var/cache/apk/*; \\
    elif command -v apt-get >/dev/null 2>&1; then \\
        apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*; \\
    elif command -v microdnf >/dev/null 2>&1; then \\
        microdnf update -y && microdnf clean all; \\
    else \\
        echo "No supported package manager detected; review the base image manually."; \\
    fi"""


def _load(path: Path) -> dict | list:
    return json.loads(path.read_text()) if path.exists() else {}


def _os_family(results_dir: Path) -> str:
    trivy = _load(results_dir / "trivy.json")
    if isinstance(trivy, dict):
        return str(trivy.get("Metadata", {}).get("OS", {}).get("Family", "")).lower()
    return ""


def _digest(results_dir: Path) -> str:
    meta = _load(results_dir / "metadata.json")
    digest = meta.get("image_digest", "") if isinstance(meta, dict) else ""
    return digest if digest and digest != "unavailable" else ""


def _finding_summary(results_dir: Path) -> tuple[int, list[dict]]:
    """Return (critical_count, top fixable findings) from enriched.json."""
    enriched = _load(results_dir / "enriched.json")
    if not isinstance(enriched, list):
        return 0, []
    crit = sum(1 for c in enriched if c.get("severity") == "CRITICAL")
    fixable = [
        c for c in enriched
        if c.get("fixed_in") not in (None, "", "N/A")
        and c.get("severity") in ("CRITICAL", "HIGH")
    ]
    fixable.sort(key=lambda c: c.get("risk_score", 0), reverse=True)
    return crit, fixable[:10]


def generate(image: str, results_dir: Path) -> Path:
    crit_count, fixable = _finding_summary(results_dir)
    family  = _os_family(results_dir)
    digest  = _digest(results_dir)

    out_dir  = Path("remediated")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"Dockerfile.{image.split(':')[0].split('/')[-1]}"

    # FROM line: pin by digest when we captured one, so the remediation build
    # is reproducible against exactly what was scanned.
    if digest:
        from_line = f"FROM {digest}\n# Tag at scan time: {image}"
    else:
        from_line = f"FROM {image}"

    upgrade_block = _PKG_UPGRADE.get(family, _FALLBACK_UPGRADE)
    user_block    = _USER_COMMANDS.get(family)
    if user_block is None:
        user_block = (
            "# OS family not recognised — add the correct non-root user commands\n"
            "# for this distro before enabling USER below."
        )

    fixable_lines = "\n".join(
        f"#   {c['id']:<20} {c.get('package','?'):<24} fix: {c.get('fixed_in','?')}"
        for c in fixable
    ) or "#   (none with a published fix at HIGH/CRITICAL severity)"

    content = f"""\
# REMEDIATION STARTING POINT — review before use; this is not a guarantee.
# Original : {image}  ({crit_count} CRITICAL CVEs at scan time)
# OS family: {family or 'unknown'}
# Generated: by docker-security-pipeline
#
# The highest-impact fix is usually a newer base tag, not in-place patching:
# in-place `upgrade` is non-reproducible and cannot fix an EOL base image.
# Top fixable HIGH/CRITICAL findings this scan saw (fix lands via upgrade):
{fixable_lines}

{from_line}

# ── Patch OS packages (stopgap until the base tag is bumped) ──────────────
{upgrade_block}

# ── Non-root user ──────────────────────────────────────────────────────────
{user_block}
# WARNING: official service images (postgres, mysql, nginx, ...) start as
# root and drop privileges in their own entrypoint. Only switch USER if your
# image does not manage this itself — otherwise you will break startup.
# USER appuser

# ── Runtime hardening (applied at run time, not build time) ───────────────
# docker run --read-only --tmpfs /tmp --cap-drop=ALL --security-opt no-new-privileges <image>

WORKDIR /app

# ── Add your application files below ─────────────────────────────────────
# COPY --chown=appuser:appgroup . .
# RUN <your build steps>
# CMD ["your", "entrypoint"]
"""
    out_path.write_text(content)
    print(f"  Remediation Dockerfile → {out_path}")
    print(f"  Base image preserved: {image}")
    print(f"  OS family: {family or 'unknown'} | digest pinned: {'yes' if digest else 'no'}")
    return out_path


if __name__ == "__main__":
    generate(sys.argv[1], Path(sys.argv[2]))

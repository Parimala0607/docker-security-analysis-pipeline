# Docker Security Analysis Pipeline

This pipeline scans Docker images for known vulnerabilities and image-hardening
issues, then turns the raw scanner output into reports that are easier to
review.

The pipeline uses Trivy, Grype, Syft, and Dockle. It compares scanner results,
generates SBOMs, enriches CVEs with EPSS and CISA KEV, writes failure logs,
applies a simple risk policy, and creates HTML reports.

The output is meant for security triage. It shows which vulnerable packages are
present in an image, which CVEs both scanners found, which CVEs only one scanner
found, and which findings are worth reviewing first. It does not prove that a
CVE is exploitable at runtime.

Licensed under MIT.

## Highlights

- Scans one Docker image or a batch of configured images.
- Uses two vulnerability scanners, Trivy and Grype, to compare coverage.
- Shows what both scanners agree on and where they disagree.
- Generates a CycloneDX SBOM with Syft.
- Runs Dockle image-hardening checks.
- Adds EPSS and CISA KEV context for prioritization.
- Writes per-scanner logs so failures are easy to debug.
- Generates per-image and batch HTML reports.
- Creates remediation Dockerfile starting points.
- Includes tests and a simple policy gate for CI-style use.

## Pipeline Flow

```text
docker pull <image>
       |
       v
run scanners in parallel
  - Trivy: vulnerability scan
  - Grype: independent vulnerability scan
  - Syft: SBOM generation
  - Dockle: image hardening checks
       |
       v
write scanner logs and status
       |
       v
reconcile Trivy and Grype CVE IDs
       |
       v
enrich with EPSS, CISA KEV, and VEX evidence
       |
       v
classify likely finding origin: base image vs application dependency
       |
       v
evaluate risk policy
       |
       v
generate remediation Dockerfile starting point and HTML reports
```

## Tools

| Tool | Purpose |
|------|---------|
| Trivy | Primary vulnerability scanner |
| Grype | Independent vulnerability scanner for cross-checking |
| Syft | CycloneDX SBOM generation |
| Dockle | Docker image hardening checks |
| EPSS | Exploit prediction score from FIRST |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| VEX | Optional local reachability/status evidence |

CVSS data comes from scanner output.

## Quick Start

```bash
# 1. Install scanners on Ubuntu 22.04+
sudo bash scripts/install_tools.sh

# 2. Create Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run tests
python3 -m pytest -q

# 4. Scan one image
bash pipeline.sh nginx:1.27

# 5. Scan all configured images
bash batch_scan.sh

# 6. Print the cross-image comparison table
python3 -m analysis.comparator
```

`batch_scan.sh` clears generated output in `results/`, `reports/`, and
`remediated/`, scans every target in `config/settings.yaml`, and writes a fresh
batch report to `reports/batch_report_<timestamp>.html`.

## Outputs

Each image scan creates a folder under `results/`:

```text
results/<timestamp>_<image>/
├── trivy.json
├── grype.json
├── sbom.json
├── dockle.json
├── enriched.json
├── validation.json
├── layers.json
├── metadata.json
├── scanner_status.json
├── policy.json
└── logs/
    ├── pull.log
    ├── trivy.log
    ├── grype.log
    ├── syft.log
    └── dockle.log
```

Reports and remediation starting points are generated separately:

```text
reports/report_<timestamp>.html
reports/batch_report_<timestamp>.html
remediated/Dockerfile.<image>
```

Generated scan outputs are ignored by git because they can be recreated from a
fresh scan.

## Failure Diagnosis

Scanner failures are retried by `pipeline.sh`. The default retry count is `2`:

```bash
SCANNER_RETRIES=3 bash pipeline.sh registry:2
```

If a scan fails, inspect:

```text
results/<scan>/logs/pull.log
results/<scan>/logs/trivy.log
results/<scan>/logs/grype.log
results/<scan>/logs/syft.log
results/<scan>/logs/dockle.log
results/<scan>/scanner_status.json
```

The comparator marks incomplete scans as `FAILED` instead of showing missing
data as zero. That keeps "no data" separate from "no vulnerabilities found."

## Risk Policy

The policy gate writes `policy.json` for every scan. By default it reports
policy status but does not fail local runs.

Current policy flags findings when any of these are true:

```text
in CISA KEV
EPSS >= 0.7
severity == CRITICAL and EPSS >= 0.2
```

For CI-style enforcement:

```bash
POLICY_ENFORCE=1 bash pipeline.sh nginx:1.27
```

Thresholds can be tuned without code changes:

```bash
POLICY_EPSS_ANY_THRESHOLD=0.8 \
POLICY_EPSS_CRITICAL_THRESHOLD=0.3 \
POLICY_ENFORCE=1 \
bash pipeline.sh nginx:1.27
```

## Methodology

Trivy-only and Grype-only findings are reported as scanner disagreement, not as
confirmed false positives or false negatives.

The report uses scanner disagreement instead:

```text
confirmed    = seen by both Trivy and Grype
Trivy-only   = seen by Trivy but not Grype
Grype-only   = seen by Grype but not Trivy
```

Grype advisory IDs are normalized to related CVE IDs where available. Both
scanners include all severities and both fixed and unfixed findings, so the
comparison uses similar inputs.

## Sample Batch Result

Sample run: 28 Docker Hub images, June 13, 2026.

| Metric | Value |
|--------|------:|
| Images scanned | 28 |
| Failed scans | 0 |
| Total findings | 16,744 |
| Critical findings | 207 |
| High findings | 2,622 |
| High + Critical findings | 2,829 |
| Findings in CISA KEV | 11 |

The full batch report is generated at:

```text
reports/batch_report_<timestamp>.html
```

## Findings From The Sample Run

### 1. Scanner agreement was higher on OS package images

For Debian and Alpine style base images, Trivy and Grype had more overlap after
ID normalization and equivalent scanner configuration.

| Image | CRIT | HIGH | Both | Trivy-only | Grype-only |
|-------|-----:|-----:|-----:|-----------:|-----------:|
| nginx:1.27 | 9 | 69 | 254 | 7 | 3 |
| httpd:2.4 | 2 | 13 | 89 | 4 | 2 |
| redis:7.4 | 3 | 7 | 56 | 5 | 2 |
| postgres:16 | 9 | 41 | 105 | 4 | 9 |
| node:22-bookworm-slim | 3 | 8 | 58 | 5 | 0 |

### 2. Most disagreement came from language ecosystems

The biggest differences showed up in language package ecosystems. Trivy
reported more findings in Go binary and PHP/Composer-heavy images. Grype
reported more findings in some Java, Erlang, and mixed images.

| Image | Ecosystem | Trivy-only | Grype-only |
|-------|-----------|-----------:|-----------:|
| wordpress:6.6 | PHP / Composer | 3670 | 25 |
| golang:1.23 | Go binaries | 2513 | 8 |
| drupal:11 | PHP / Composer | 2149 | 10 |
| php:8.3-apache | PHP / Composer | 357 | 0 |
| rabbitmq:3-management | Erlang / OS packages | 0 | 130 |
| mongo:7 | mixed | 0 | 65 |
| tomcat:10.1 | Java / Maven | 0 | 45 |
| jenkins:lts-jdk21 | Java / Maven | 4 | 41 |

Trivy-only and Grype-only findings stay visible because the results change by
package ecosystem.

### 3. Raw counts matter next to percentages

Small images can show big disagreement percentages with very few findings.
For example, `alpine:3.20` has one Grype-only finding, so it shows
`100%` Grype-only disagreement. That is different from a 100% rate across
hundreds of findings.

The comparator prints raw counts beside rates for this reason.

### 4. CVSS alone was too noisy for prioritization

The sample batch produced 2,829 High/Critical findings, but only 11 findings
appeared in CISA KEV. Raw severity alone would hide the known-exploited items
inside a much larger backlog.

The report includes priority, EPSS, KEV, and VEX context.

## Remediation Model

Generated Dockerfiles in `remediated/` are remediation starting points. Review
and test them before use.

The remediation generator:

```text
uses the scanned image digest when available
chooses package-manager commands based on detected OS family
summarizes fixable high/critical findings
adds a non-root user pattern when the OS family is known
includes runtime hardening suggestions
```

In many cases, remediation starts by moving the `FROM` line to a newer base
image. In-place package upgrades can help as a stopgap, but they are less
reproducible and cannot fix end-of-life base images.

## Limitations

The pipeline identifies known vulnerabilities and hardening issues in image
contents. It does not prove that a CVE is exploitable in a deployed service.

Limits:

```text
Runtime reachability is unknown unless VEX or external context is supplied.
Scanner results depend on scanner DB versions and image digests.
The latest-tagged images are moving targets.
Language ecosystem coverage differs between scanners.
Some findings may be unreachable, mitigated, or irrelevant in a specific deployment.
```

For production use, pair this output with service ownership, exposure,
compensating controls, runtime configuration, and patch windows.

## Project Structure

```text
docker-security-pipeline/
├── pipeline.sh                       # Single-image orchestrator
├── batch_scan.sh                     # Batch scan and aggregate report
├── config/settings.yaml              # Image list and thresholds
├── scanners/                         # Scanner wrappers
│   ├── trivy_scan.sh
│   ├── grype_scan.sh
│   ├── dockle_scan.sh
│   └── syft_sbom.sh
├── analysis/                         # Parse, reconcile, enrich, classify, gate
│   ├── models.py
│   ├── parsers.py
│   ├── fp_fn_validator.py
│   ├── disagreement_breakdown.py
│   ├── epss_scorer.py
│   ├── layer_attribution.py
│   ├── policy_gate.py
│   ├── scanner_status.py
│   ├── comparator.py
│   ├── vex.py
│   └── scan_metadata.py
├── remediation/
│   └── dockerfile_generator.py
├── reports/
│   ├── report_generator.py
│   ├── batch_report_generator.py
│   └── templates/
├── tests/
└── .github/workflows/
```

## Design Principles

- Keep the raw scanner evidence available for review.
- Show scanner disagreement instead of hiding it behind one score.
- Keep generated scan data separate from source code.
- Use EPSS, KEV, and VEX to help prioritize review.
- Write per-scanner logs so failures can be diagnosed.
- Treat generated Dockerfiles as remediation starting points.

## Environment

Tested with:

```text
Ubuntu 22.04 LTS
Python 3.12
Docker Engine 24+
Trivy 0.70.0
Grype 0.112.0
Syft 1.44.0
Dockle 0.4.15
```

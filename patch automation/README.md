# Rapid7 InsightVM to Automox Sync

This tool exports active Critical and Severe InsightVM findings, joins Rapid7
vulnerability IDs to CVEs, writes an Automox-compatible Rapid7 CSV, and can
upload it to Automox Vulnerability Sync.

It uses the InsightVM Cloud Integrations API v4. The CSV always remains on disk
for auditability. Uploading to Automox is opt-in.

## Requirements

- Python 3.10+
- Rapid7 InsightVM API key
- Automox API key and numeric organization ID when using `--upload`
- Automox Vulnerability Sync enabled

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp .env.example .env
```

Export the values from `.env` into your shell or secret-management system.
The application intentionally does not parse `.env` files itself.

```bash
set -a
source .env
set +a
```

## Run

Create the CSV without sending anything to Automox:

```bash
rapid7-automox-sync --output rapid7-findings.csv
```

Create and upload the CSV:

```bash
rapid7-automox-sync --output rapid7-findings.csv --upload
```

Useful options:

```text
--region ca            Rapid7 region: us, us2, us3, eu, ca, au, ap, aps2, me1
--page-size 500        Rapid7 API page size
--hostname-fallback ip Use an asset IP when Rapid7 has no hostname
--verbose              Enable debug logging
```

The output format is:

```csv
Host,CVE,Severity
server01.example.com,CVE-2026-1234,critical
server02.example.com,CVE-2026-5678,high
```

Rapid7 `Severe` is mapped to Automox `high`. Findings without a CVE or a usable
hostname are skipped and reported in the run summary.

## Scheduling

Run after InsightVM scans using a scheduler such as cron, a Kubernetes CronJob,
or a CI system. Store API keys in the scheduler's secret store. Start without
`--upload`, inspect the CSV and skipped counts, then enable upload.

## Security Notes

This is a CLI integration rather than a web application, so some OWASP Top 10
classes such as browser XSS, CSRF, and session management do not directly apply.
The implementation still includes controls for the applicable risks:

- API traffic is restricted to HTTPS and expected Rapid7/Automox hostnames.
- TLS certificate validation is performed by Python's default trust store with
  TLS 1.2 or newer.
- API keys are read from environment variables and are not logged.
- Generated CSV files are written with `0600` permissions.
- CSV cells are escaped to reduce spreadsheet formula-injection risk.
- Multipart upload filenames are sanitized.
- Uploading to Automox is opt-in with `--upload`.
- The project has no third-party runtime dependencies.

Treat the generated CSV as sensitive because it contains vulnerability and asset
data. Store it only in protected locations and remove old exports according to
your retention policy.

## Test

```bash
python -m unittest discover -s tests -v
```

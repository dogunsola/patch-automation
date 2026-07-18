import csv
import stat
import tempfile
import unittest
from pathlib import Path

from rapid7_automox_sync.models import AutomoxFinding
from rapid7_automox_sync.transform import (
    build_catalog,
    transform_assets,
    write_automox_csv,
)


class TransformTests(unittest.TestCase):
    def test_build_catalog_extracts_and_maps_cves(self) -> None:
        catalog = build_catalog(
            [
                {
                    "id": "vuln-1",
                    "severity": "Critical",
                    "cves": "CVE-2025-1234, cve-2025-56789",
                    "name": "Example Service",
                },
                {"id": "vuln-2", "severity": "Severe", "cves": "CVE-2024-9999", "name": "Example Service"},
                {"id": "moderate", "severity": "Moderate", "cves": "CVE-2020-0001"},
            ]
        )
        self.assertEqual(
            catalog,
            {
                "vuln-1": (("CVE-2025-1234", "CVE-2025-56789"), "critical", "Example Service"),
                "vuln-2": (("CVE-2024-9999",), "high", "Example Service"),
            },
        )

    def test_transform_uses_active_findings_and_deduplicates(self) -> None:
        catalog = {
            "vuln-1": (("CVE-2025-1234",), "critical", "Example Service"),
            "no-cve": ((), "high", "Example Service"),
            "microsoft": (("CVE-2025-9999",), "critical", "Microsoft Windows Server"),
        }
        assets = [
            {
                "host_name": "host.example.com",
                "new": [{"vulnerability_id": "vuln-1"}],
                "same": [
                    {"vulnerability_id": "vuln-1"},
                    {"vulnerability_id": "no-cve"},
                    {"vulnerability_id": "missing"},
                ],
                "remediated": [{"vulnerability_id": "vuln-1"}],
            },
            {"ip": "10.0.0.2", "new": [{"vulnerability_id": "vuln-1"}]},
        ]
        findings, stats = transform_assets(assets, catalog)
        self.assertEqual(
            findings,
            [
                AutomoxFinding(
                    software="Example Service",
                    hosts=("host.example.com",),
                    cves=("CVE-2025-1234",),
                    severity="critical",
                )
            ],
        )
        self.assertEqual(stats.assets_seen, 2)
        self.assertEqual(stats.findings_without_cve, 1)
        self.assertEqual(stats.assets_without_host, 1)
        self.assertEqual(stats.vulnerability_ids_not_in_catalog, 1)

    def test_ip_fallback_and_csv_format(self) -> None:
        findings, _ = transform_assets(
            [{"ip": "10.0.0.2", "new": [{"vulnerability_id": "vuln-1"}]}],
            {"vuln-1": (("CVE-2025-1234",), "critical", "Example Service")},
            hostname_fallback="ip",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.csv"
            write_automox_csv(output, findings)
            with output.open(newline="", encoding="utf-8") as file:
                rows = list(csv.reader(file))
        self.assertEqual(
            rows,
            [
                ["Software", "Host", "CVEs", "Severity"],
                ["Example Service", "10.0.0.2", "CVE-2025-1234", "critical"],
            ],
        )

    def test_csv_formula_cells_are_escaped_and_file_is_private(self) -> None:
        findings = [
            AutomoxFinding(
                software="=cmd|calc",
                hosts=("host.example.com",),
                cves=("CVE-2025-1234",),
                severity="critical",
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.csv"
            write_automox_csv(output, findings)
            with output.open(newline="", encoding="utf-8") as file:
                rows = list(csv.reader(file))
            mode = stat.S_IMODE(output.stat().st_mode)
        self.assertEqual(rows[1], ["'=cmd|calc", "host.example.com", "CVE-2025-1234", "critical"])
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()

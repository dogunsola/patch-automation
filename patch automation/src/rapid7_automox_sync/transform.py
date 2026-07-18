import csv
import os
import re
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import AutomoxFinding, TransformStats

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
SEVERITY_MAP = {"critical": "critical", "severe": "high"}
ACTIVE_FINDING_FIELDS = ("new", "same")
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
MICROSOFT_TOKENS = ("microsoft", "windows", "office", "azure", "sql server")


def build_catalog(
    vulnerabilities: Iterable[dict[str, Any]],
) -> dict[str, tuple[tuple[str, ...], str, str]]:
    catalog: dict[str, tuple[tuple[str, ...], str, str]] = {}
    for vulnerability in vulnerabilities:
        vulnerability_id = str(vulnerability.get("id", "")).strip()
        severity = SEVERITY_MAP.get(str(vulnerability.get("severity", "")).lower())
        if not vulnerability_id or not severity:
            continue
        cves = tuple(sorted(set(CVE_PATTERN.findall(str(vulnerability.get("cves", ""))))))
        software = str(vulnerability.get("name") or vulnerability.get("title") or "Unknown Service")
        software = software.strip() or "Unknown Service"
        catalog[vulnerability_id] = (
            tuple(cve.upper() for cve in cves),
            severity,
            software,
        )
    return catalog


def transform_assets(
    assets: Iterable[dict[str, Any]],
    catalog: dict[str, tuple[tuple[str, ...], str, str]],
    hostname_fallback: str = "skip",
) -> tuple[list[AutomoxFinding], TransformStats]:
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    assets_seen = 0
    findings_without_cve = 0
    assets_without_host = 0
    unknown_ids = 0

    for asset in assets:
        assets_seen += 1
        host = _clean_cell(str(asset.get("host_name") or "").strip())
        if not host and hostname_fallback == "ip":
            host = _clean_cell(str(asset.get("ip") or "").strip())
        if not host:
            assets_without_host += 1
            continue

        for field in ACTIVE_FINDING_FIELDS:
            for item in asset.get(field) or []:
                vulnerability_id = str(item.get("vulnerability_id", "")).strip()
                catalog_entry = catalog.get(vulnerability_id)
                if catalog_entry is None:
                    unknown_ids += 1
                    continue
                cves, severity, software = catalog_entry
                if not cves:
                    findings_without_cve += 1
                    continue
                if _is_microsoft_software(software):
                    continue
                key = (software, severity)
                group = findings.setdefault(
                    key,
                    {"software": software, "severity": severity, "hosts": set(), "cves": set()},
                )
                group["hosts"].add(host)
                group["cves"].update(cves)

    ordered = [
        AutomoxFinding(
            software=entry["software"],
            hosts=tuple(sorted(entry["hosts"])),
            cves=tuple(sorted(entry["cves"])),
            severity=entry["severity"],
        )
        for entry in sorted(findings.values(), key=lambda item: (item["software"], item["severity"]))
    ]
    return ordered, TransformStats(
        assets_seen=assets_seen,
        findings_written=len(ordered),
        findings_without_cve=findings_without_cve,
        assets_without_host=assets_without_host,
        vulnerability_ids_not_in_catalog=unknown_ids,
    )


def write_automox_csv(path: Path, findings: Iterable[AutomoxFinding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    os.chmod(temp_name, 0o600)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(("Software", "Hosts", "CVEs", "Severity"))
            writer.writerows(
                (
                    _clean_cell(item.software),
                    "; ".join(_clean_cell(host) for host in item.hosts),
                    "; ".join(_clean_cell(cve) for cve in item.cves),
                    item.severity,
                )
                for item in findings
            )
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _clean_cell(value: str) -> str:
    cleaned = value.replace("\x00", "").strip()
    if cleaned.startswith(CSV_FORMULA_PREFIXES):
        return f"'{cleaned}"
    return cleaned


def _is_microsoft_software(software: str) -> bool:
    lowered = software.lower()
    return any(token in lowered for token in MICROSOFT_TOKENS)

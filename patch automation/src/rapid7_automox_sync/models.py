from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class AutomoxFinding:
    software: str
    hosts: tuple[str, ...]
    cves: tuple[str, ...]
    severity: str


@dataclass(frozen=True)
class TransformStats:
    assets_seen: int
    findings_written: int
    findings_without_cve: int
    assets_without_host: int
    vulnerability_ids_not_in_catalog: int


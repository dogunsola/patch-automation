import argparse
import logging
import os
import stat
from pathlib import Path

from .automox import AutomoxClient
from .rapid7 import Rapid7Client, VALID_REGIONS
from .transform import build_catalog, transform_assets, write_automox_csv

LOG = logging.getLogger(__name__)


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def safe_output_path(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise SystemExit("Refusing to write output through a symbolic link")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export critical and severe InsightVM findings to Automox."
    )
    parser.add_argument(
        "--region",
        choices=sorted(VALID_REGIONS),
        default=os.environ.get("RAPID7_REGION", "us"),
        help="Rapid7 Insight Platform region (default: RAPID7_REGION or us)",
    )
    parser.add_argument("--page-size", type=positive_int, default=500)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("rapid7-findings.csv"),
        help="CSV output path",
    )
    parser.add_argument(
        "--hostname-fallback",
        choices=("skip", "ip"),
        default="skip",
        help="Behavior when an InsightVM asset has no hostname",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload the generated CSV to Automox Vulnerability Sync",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    rapid7 = Rapid7Client(
        api_key=required_env("RAPID7_API_KEY"),
        region=args.region,
        page_size=args.page_size,
    )
    LOG.info("Downloading Rapid7 Critical and Severe vulnerability catalog")
    catalog = build_catalog(rapid7.iter_vulnerability_catalog())
    LOG.info("Catalog contains %s Critical/Severe vulnerability IDs", len(catalog))

    LOG.info("Downloading affected Rapid7 assets and active findings")
    findings, stats = transform_assets(
        rapid7.iter_affected_assets(),
        catalog,
        hostname_fallback=args.hostname_fallback,
    )
    args.output = safe_output_path(args.output)
    write_automox_csv(args.output, findings)
    LOG.info("Wrote %s unique findings to %s", len(findings), args.output)
    LOG.info(
        "Summary: assets=%s, no-CVE=%s, no-host=%s, unknown-vulnerability-id=%s",
        stats.assets_seen,
        stats.findings_without_cve,
        stats.assets_without_host,
        stats.vulnerability_ids_not_in_catalog,
    )

    if args.upload:
        if not findings:
            raise SystemExit("CSV has no findings; refusing to upload an empty report")
        automox = AutomoxClient(
            api_key=required_env("AUTOMOX_API_KEY"),
            organization_id=int(required_env("AUTOMOX_ORG_ID")),
        )
        result = automox.upload_rapid7_csv(args.output)
        LOG.info(
            "Automox accepted action set id=%s status=%s",
            result.get("id", "unknown"),
            result.get("status", "unknown"),
        )
    else:
        LOG.info("Dry run complete; use --upload to send this CSV to Automox")

    try:
        mode = stat.S_IMODE(args.output.stat().st_mode)
        if mode & 0o077:
            LOG.warning("%s is readable by group/other; consider chmod 600", args.output)
    except OSError:
        pass


if __name__ == "__main__":
    main()

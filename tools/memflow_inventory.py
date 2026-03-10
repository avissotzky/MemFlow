"""
tools.memflow_inventory
=======================
**MF-020 — Inventory Discovery Tool.**

Scans a case directory's CSV folder and produces a precise inventory of every
CSV file found, including headers, row counts, SHA-256 hashes, and detected
anomalies (duplicate headers, empty files, OS-locked files).

Outputs
-------
- ``<case>/docs/03_csv_inventory.json``  — Machine-readable inventory.
- ``<case>/artifacts/_inventory_manifest.csv`` — Flat CSV manifest.

Usage
-----
::

    python -m tools.memflow_inventory --case C:\\Cases\\IR-2025-042

"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def detect_anomalies(
    filepath: Path,
    table: Optional[RawTable],
    error: Optional[str],
) -> List[str]:
    """Return a list of anomaly tags for a single CSV file.

    Possible anomaly strings
    ------------------------
    - ``"empty_file"``            — file has no header row at all.
    - ``"empty_data"``            — headers exist but zero data rows.
    - ``"duplicate_header: <X>"`` — header *X* appears more than once.
    - ``"read_error: <msg>"``     — file could not be opened / parsed.
    - ``"locked_by_os"``          — PermissionError on read.
    """
    anomalies: List[str] = []

    if error:
        anomalies.append(f"read_error: {error}")
        return anomalies

    if table is None:
        return anomalies

    # Completely empty file (no headers)
    if not table.headers:
        anomalies.append("empty_file")
        return anomalies

    # Headers present but no data rows
    if table.row_count == 0:
        anomalies.append("empty_data")

    # Duplicate header names
    seen: set[str] = set()
    dupes: set[str] = set()
    for header in table.headers:
        if header in seen:
            dupes.add(header)
        seen.add(header)
    for dupe in sorted(dupes):
        anomalies.append(f"duplicate_header: {dupe}")

    return anomalies


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

def scan_csv_directory(scan_dir: Path) -> List[Dict[str, Any]]:
    """Scan *scan_dir* for ``*.csv`` files and return inventory entries.

    Each entry is a dict with keys:
    ``filename``, ``filepath``, ``headers``, ``row_count``,
    ``sha256``, ``ingest_errors``, ``anomalies``.
    """
    if not scan_dir.is_dir():
        logger.error("Scan directory does not exist: %s", scan_dir)
        return []

    csv_files = sorted(scan_dir.glob("*.csv"))
    logger.info("Found %d CSV file(s) in %s", len(csv_files), scan_dir)

    entries: List[Dict[str, Any]] = []

    for filepath in csv_files:
        entry: Dict[str, Any] = {
            "filename": filepath.name,
            "filepath": str(filepath.resolve()),
        }

        table: Optional[RawTable] = None
        error: Optional[str] = None

        try:
            table = read_csv_safe(filepath)
        except PermissionError:
            error = "locked_by_os"
            logger.warning("File locked by OS: %s", filepath)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            logger.warning("Failed to read %s: %s", filepath, exc)

        if table is not None:
            entry["headers"] = table.headers
            entry["row_count"] = table.row_count
            entry["sha256"] = table.sha256
            entry["ingest_errors"] = len(table.ingest_errors)
        else:
            entry["headers"] = []
            entry["row_count"] = 0
            entry["sha256"] = ""
            entry["ingest_errors"] = 0

        entry["anomalies"] = detect_anomalies(filepath, table, error)
        entries.append(entry)

    return entries


def build_inventory(case_dir: Path, scan_dir: Path) -> Dict[str, Any]:
    """Build the complete inventory document."""
    entries = scan_csv_directory(scan_dir)

    # Aggregate anomaly summaries
    dup_header_files = [
        e["filename"]
        for e in entries
        if any(a.startswith("duplicate_header") for a in e["anomalies"])
    ]
    empty_files = [
        e["filename"]
        for e in entries
        if "empty_file" in e["anomalies"] or "empty_data" in e["anomalies"]
    ]
    locked_files = [
        e["filename"]
        for e in entries
        if any("locked_by_os" in a for a in e["anomalies"])
    ]
    error_files = [
        e["filename"]
        for e in entries
        if any(a.startswith("read_error") for a in e["anomalies"])
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_directory": str(case_dir.resolve()),
        "scan_directory": str(scan_dir.resolve()),
        "total_files": len(entries),
        "files": entries,
        "anomalies_summary": {
            "duplicate_headers": dup_header_files,
            "empty_files": empty_files,
            "locked_files": locked_files,
            "read_errors": error_files,
        },
    }


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_inventory_json(inventory: Dict[str, Any], path: Path) -> Path:
    """Serialise the inventory to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2, ensure_ascii=False)
    logger.info("Wrote JSON inventory: %s", path)
    return path


def write_inventory_manifest(inventory: Dict[str, Any], path: Path) -> Path:
    """Write a flat CSV manifest summarising the inventory."""
    table = RawTable(
        headers=["filename", "row_count", "sha256", "header_count", "anomalies"],
    )
    for entry in inventory["files"]:
        table.rows.append([
            entry["filename"],
            str(entry["row_count"]),
            entry["sha256"],
            str(len(entry["headers"])),
            "; ".join(entry["anomalies"]) if entry["anomalies"] else "",
        ])

    write_csv_safe(table, path)
    logger.info("Wrote manifest CSV: %s", path)
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_inventory",
        description="MF-020: Scan a case directory and inventory all CSV files.",
    )
    parser.add_argument(
        "--case", "-c",
        required=True,
        type=Path,
        help="Path to the investigation root directory.",
    )
    parser.add_argument(
        "--in", "-i",
        dest="in_path",
        type=Path,
        default=None,
        help="Directory to scan for CSVs (default: <case>/csv/).",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output base directory (default: <case>).",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns an exit code (0 = OK, 1 = anomalies, 2 = fatal)."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # -- Logging ------------------------------------------------------------ #
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    case_dir: Path = args.case.resolve()
    scan_dir: Path = (args.in_path or (case_dir / "csv")).resolve()
    out_dir: Path = (args.out or case_dir).resolve()

    # -- Startup validation ------------------------------------------------- #
    if not case_dir.exists():
        logger.warning("Case directory does not exist, creating: %s", case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)

    if not scan_dir.is_dir():
        logger.error("Input directory does not exist or is not a directory: %s", scan_dir)
        return 2

    # -- Build inventory ---------------------------------------------------- #
    inventory = build_inventory(case_dir, scan_dir)

    # -- Write outputs ------------------------------------------------------ #
    json_path = out_dir / "docs" / "03_csv_inventory.json"
    manifest_path = out_dir / "artifacts" / "_inventory_manifest.csv"

    write_inventory_json(inventory, json_path)
    write_inventory_manifest(inventory, manifest_path)

    # -- Summary & exit code ------------------------------------------------ #
    summary = inventory["anomalies_summary"]
    has_anomalies = any(
        bool(v) for v in summary.values()
    )

    logger.info(
        "Inventory complete: %d file(s) scanned, anomalies=%s",
        inventory["total_files"],
        "YES" if has_anomalies else "none",
    )

    return 1 if has_anomalies else 0


if __name__ == "__main__":
    sys.exit(main())

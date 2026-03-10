"""
tools.memflow_parse_generic
============================
**MF-050 — Standalone Parsing Tool.**

Wraps :func:`memflow_parser.engine.parse_table` in a CLI that follows the
MemFlow CLI contract (``--case``, ``--in``, ``--out``, ``--log-level``).

The tool automatically locates the matching YAML spec for the input CSV by
looking in ``memflow_specs/`` (or a user-supplied ``--specs`` directory).

Outputs
-------
- ``<out>/typed_<table>.csv``   — The typed, normalised CSV.
- ``<out>/_parsing_errors.csv`` — Append-mode log of all conversion errors.

Usage
-----
::

    python -m tools.memflow_parse_generic \\
        --case C:\\Cases\\IR-2025-042 \\
        --in   C:\\Cases\\IR-2025-042\\csv\\process.csv

Shortcut for a specific table::

    python -m tools.memflow_parse_generic \\
        --case ./case1 \\
        --in   ./case1/csv/process.csv

"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import List, Optional

from memflow_parser.engine import ErrorLog, TypedTable, parse_table

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Spec discovery
# ---------------------------------------------------------------------------

def find_spec_for_csv(csv_path: Path, specs_dir: Path) -> Optional[Path]:
    """Locate the YAML spec that matches a given CSV filename.

    The convention is ``<table_stem>.yaml`` in *specs_dir*.
    For ``process.csv`` we look for ``process.yaml``.

    Parameters
    ----------
    csv_path : Path
        The raw CSV file.
    specs_dir : Path
        Directory containing YAML spec files.

    Returns
    -------
    Path or None
        Resolved path to the spec, or ``None`` if not found.
    """
    table_stem = csv_path.stem  # "process" from "process.csv"
    spec_path = specs_dir / f"{table_stem}.yaml"
    if spec_path.is_file():
        return spec_path
    logger.warning(
        "No spec found for '%s' (looked for %s).", csv_path.name, spec_path,
    )
    return None


# ---------------------------------------------------------------------------
# Error CSV writer (append mode)
# ---------------------------------------------------------------------------

def write_parsing_errors(errors: ErrorLog, path: Path, source_file: str) -> Optional[Path]:
    """Append parsing errors to ``_parsing_errors.csv``.

    Creates the file with a header row if it does not yet exist.

    Parameters
    ----------
    errors : ErrorLog
        List of :class:`ParseError` instances to write.
    path : Path
        Path to the ``_parsing_errors.csv`` file.
    source_file : str
        Name of the source CSV (included in every row for traceability).

    Returns
    -------
    Path or None
        The written path, or ``None`` if there were no errors.
    """
    if not errors:
        return None

    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists()

    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        if write_header:
            writer.writerow([
                "source_file", "row_index", "column",
                "raw_value", "expected_type", "error",
            ])
        for err in errors:
            writer.writerow([
                source_file,
                str(err.row_index),
                err.column,
                err.raw_value,
                err.expected_type,
                err.error,
            ])

    logger.info("Appended %d error(s) to %s", len(errors), path)
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_parse_generic",
        description=(
            "MF-050: Parse a raw CSV into a typed CSV using a YAML spec."
        ),
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
        required=True,
        type=Path,
        help="Path to the raw CSV file (or directory of CSVs) to parse.",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for typed CSVs (default: <case>/csv/).",
    )
    parser.add_argument(
        "--specs", "-s",
        type=Path,
        default=None,
        help="Directory containing YAML spec files (default: memflow_specs/).",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser


def _parse_single_file(
    csv_path: Path,
    specs_dir: Path,
    out_dir: Path,
) -> int:
    """Parse one CSV file.  Returns 0 on success, 1 on parse errors, 2 on fatal."""
    spec_path = find_spec_for_csv(csv_path, specs_dir)
    if spec_path is None:
        logger.error(
            "Cannot parse '%s': no matching spec in %s", csv_path.name, specs_dir,
        )
        return 2

    try:
        typed_table, errors = parse_table(csv_path, spec_path)
    except Exception as exc:
        logger.error("Fatal error parsing '%s': %s", csv_path.name, exc)
        return 2

    # -- Write typed CSV ---------------------------------------------------- #
    from memflow_common.csv_io import write_csv_safe

    out_filename = f"typed_{typed_table.table_name}.csv"
    out_path = out_dir / out_filename
    raw_for_write = typed_table.to_raw_table()
    write_csv_safe(raw_for_write, out_path)
    logger.info("Typed CSV written: %s (%d rows)", out_path, typed_table.row_count)

    # -- Write parsing errors (append) -------------------------------------- #
    error_path = out_dir / "_parsing_errors.csv"
    write_parsing_errors(errors, error_path, csv_path.name)

    if errors:
        logger.warning(
            "%d conversion error(s) in '%s' — see %s",
            len(errors), csv_path.name, error_path,
        )
        return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns 0 on success, 1 on parse errors, 2 on fatal."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # -- Logging ------------------------------------------------------------ #
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    case_dir: Path = args.case.resolve()
    in_path: Path = args.in_path.resolve()
    out_dir: Path = (args.out or (case_dir / "csv")).resolve()
    specs_dir: Path = (args.specs or Path("memflow_specs")).resolve()

    # -- Startup validation ------------------------------------------------- #
    if not case_dir.exists():
        logger.warning("Case directory does not exist, creating: %s", case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        logger.error("Input path does not exist: %s", in_path)
        return 2

    if not specs_dir.is_dir():
        logger.error("Specs directory does not exist: %s", specs_dir)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    # -- Determine files to parse ------------------------------------------- #
    if in_path.is_dir():
        csv_files = sorted(in_path.glob("*.csv"))
        if not csv_files:
            logger.error("No CSV files found in: %s", in_path)
            return 2
        logger.info("Found %d CSV file(s) to parse in %s", len(csv_files), in_path)
    else:
        csv_files = [in_path]

    # -- Parse each file ---------------------------------------------------- #
    worst_code = 0
    for csv_path in csv_files:
        code = _parse_single_file(csv_path, specs_dir, out_dir)
        worst_code = max(worst_code, code)

    # -- Summary ------------------------------------------------------------ #
    logger.info(
        "Parsing complete: %d file(s) processed, exit code %d.",
        len(csv_files), worst_code,
    )
    return worst_code


if __name__ == "__main__":
    sys.exit(main())

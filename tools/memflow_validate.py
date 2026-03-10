"""
tools.memflow_validate
======================
**MF-070 — Validation Runner (The Truth Checker).**

Compares raw inventory data against typed CSV output to verify that the
MemFlow pipeline upheld its "zero data loss" guarantee.

Checks
------
1. **Parity** — Does ``raw.row_count == typed.row_count`` for every table?
2. **Constraints** — Do all columns defined in the YAML spec contain non-null
   values where the spec declares a non-``raw``/``string`` type?
3. **Relations** (optional) — Does ``pid`` in ``typed_net.csv`` exist in
   ``typed_process.csv``?

Outputs
-------
- ``<case>/artifacts/validation_report.md`` — Human-readable Pass/Fail table.
- Exit code ``1`` if **any** check fails.

Usage
-----
::

    python -m tools.memflow_validate \\
        --case C:\\Cases\\IR-2025-042

    python -m tools.memflow_validate \\
        --case ./case1 \\
        --in   ./case1/csv \\
        --specs memflow_specs
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from memflow_common.csv_io import RawTable, read_csv_safe

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """One row in the validation report."""

    table: str
    check: str          # "parity", "constraint", "relation"
    status: str         # "PASS" or "FAIL"
    detail: str = ""


@dataclass
class ValidationReport:
    """Aggregated validation results."""

    generated_at: str = ""
    case_directory: str = ""
    results: List[CheckResult] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return any(r.status == "FAIL" for r in self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.status == "PASS")

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")


# ---------------------------------------------------------------------------
# Manifest loader
# ---------------------------------------------------------------------------

def load_manifest(manifest_path: Path) -> Dict[str, Dict[str, Any]]:
    """Load ``_inventory_manifest.csv`` into a dict keyed by filename.

    Returns
    -------
    dict
        ``{ "process.csv": {"row_count": 42, "sha256": "...", ...}, ... }``
    """
    table = read_csv_safe(manifest_path)
    manifest: Dict[str, Dict[str, Any]] = {}

    # Expected headers: filename, row_count, sha256, header_count, anomalies
    try:
        idx_filename = table.headers.index("filename")
        idx_row_count = table.headers.index("row_count")
        idx_sha256 = table.headers.index("sha256")
        idx_header_count = table.headers.index("header_count")
    except ValueError as exc:
        logger.error("Manifest CSV missing expected column: %s", exc)
        return manifest

    for row in table.rows:
        filename = row[idx_filename]
        try:
            row_count = int(row[idx_row_count])
        except (ValueError, IndexError):
            row_count = 0
        try:
            header_count = int(row[idx_header_count])
        except (ValueError, IndexError):
            header_count = 0

        manifest[filename] = {
            "row_count": row_count,
            "sha256": row[idx_sha256] if idx_sha256 < len(row) else "",
            "header_count": header_count,
        }

    logger.info("Loaded manifest: %d entries from %s", len(manifest), manifest_path)
    return manifest


# ---------------------------------------------------------------------------
# YAML spec loader (lightweight — only need column names and required-ness)
# ---------------------------------------------------------------------------

def _load_spec_columns(spec_path: Path) -> Dict[str, str]:
    """Parse a YAML spec and return ``{column_name: type_string}``.

    This is intentionally lightweight — we only need column names and their
    declared types for constraint checking.
    """
    import re
    col_re = re.compile(
        r"""
        ^\s+                           # leading indent
        (?:"([^"]+)"|(\S+))            # column name — quoted or bare
        \s*:\s*                        # colon separator
        \{\s*type\s*:\s*"([^"]+)"\s*\} # { type: "typename" }
        """,
        re.VERBOSE,
    )

    columns: Dict[str, str] = {}
    text = spec_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        match = col_re.match(line)
        if match:
            col_name = match.group(1) or match.group(2)
            col_type = match.group(3)
            columns[col_name] = col_type

    return columns


# ---------------------------------------------------------------------------
# Check 1: Parity — raw row count vs typed row count
# ---------------------------------------------------------------------------

def check_parity(
    manifest: Dict[str, Dict[str, Any]],
    typed_dir: Path,
) -> List[CheckResult]:
    """Compare manifest row counts against ``typed_*.csv`` row counts.

    For every ``typed_<table>.csv`` found in *typed_dir*, look up the
    corresponding ``<table>.csv`` in the manifest and verify that the
    row counts match.
    """
    results: List[CheckResult] = []

    typed_files = sorted(typed_dir.glob("typed_*.csv"))
    if not typed_files:
        logger.warning("No typed_*.csv files found in %s", typed_dir)
        return results

    for typed_path in typed_files:
        # typed_process.csv  →  process.csv
        table_stem = typed_path.stem.removeprefix("typed_")
        raw_filename = f"{table_stem}.csv"

        typed_table = read_csv_safe(typed_path)
        typed_count = typed_table.row_count

        if raw_filename not in manifest:
            results.append(CheckResult(
                table=raw_filename,
                check="parity",
                status="FAIL",
                detail=(
                    f"No manifest entry for '{raw_filename}'. "
                    f"typed_{table_stem}.csv has {typed_count} rows."
                ),
            ))
            logger.warning("Parity FAIL: '%s' not in manifest.", raw_filename)
            continue

        raw_count = manifest[raw_filename]["row_count"]

        if raw_count == typed_count:
            results.append(CheckResult(
                table=raw_filename,
                check="parity",
                status="PASS",
                detail=f"raw={raw_count}, typed={typed_count}",
            ))
            logger.info("Parity PASS: %s (%d rows)", raw_filename, raw_count)
        else:
            results.append(CheckResult(
                table=raw_filename,
                check="parity",
                status="FAIL",
                detail=f"ROW MISMATCH — raw={raw_count}, typed={typed_count}",
            ))
            logger.warning(
                "Parity FAIL: %s — raw=%d, typed=%d",
                raw_filename, raw_count, typed_count,
            )

    return results


# ---------------------------------------------------------------------------
# Check 2: Constraints — non-null required columns
# ---------------------------------------------------------------------------

def check_constraints(
    typed_dir: Path,
    specs_dir: Path,
) -> List[CheckResult]:
    """Verify that typed columns defined in YAML specs contain non-null values.

    For each ``typed_<table>.csv`` with a matching spec, iterate all rows and
    flag columns that have empty/null values where a typed column
    (non-``raw``/``string``) is declared.
    """
    results: List[CheckResult] = []

    typed_files = sorted(typed_dir.glob("typed_*.csv"))
    if not typed_files:
        return results

    for typed_path in typed_files:
        table_stem = typed_path.stem.removeprefix("typed_")
        spec_path = specs_dir / f"{table_stem}.yaml"

        if not spec_path.is_file():
            logger.debug("No spec for '%s', skipping constraint check.", table_stem)
            continue

        spec_columns = _load_spec_columns(spec_path)
        if not spec_columns:
            continue

        typed_table = read_csv_safe(typed_path)

        # Build column index mapping
        col_indices: Dict[str, int] = {}
        for idx, hdr in enumerate(typed_table.headers):
            if hdr in spec_columns:
                col_indices[hdr] = idx

        # Identify typed (non-raw/string) columns as "required"
        required_cols = {
            name for name, ctype in spec_columns.items()
            if ctype not in ("raw", "string") and name in col_indices
        }

        if not required_cols:
            results.append(CheckResult(
                table=f"{table_stem}.csv",
                check="constraint",
                status="PASS",
                detail="No typed (non-raw/string) columns to check.",
            ))
            continue

        # Count nulls per required column
        null_counts: Dict[str, int] = {col: 0 for col in required_cols}
        for row in typed_table.rows:
            for col_name in required_cols:
                col_idx = col_indices[col_name]
                if col_idx < len(row):
                    value = row[col_idx].strip()
                    if not value:
                        null_counts[col_name] += 1

        failed_cols = {col: cnt for col, cnt in null_counts.items() if cnt > 0}

        if not failed_cols:
            results.append(CheckResult(
                table=f"{table_stem}.csv",
                check="constraint",
                status="PASS",
                detail=(
                    f"All {len(required_cols)} typed column(s) have "
                    f"non-null values across {typed_table.row_count} rows."
                ),
            ))
            logger.info("Constraint PASS: %s.csv", table_stem)
        else:
            detail_parts = [
                f"{col}: {cnt} null(s)" for col, cnt in sorted(failed_cols.items())
            ]
            results.append(CheckResult(
                table=f"{table_stem}.csv",
                check="constraint",
                status="FAIL",
                detail=f"Null values in typed columns — {'; '.join(detail_parts)}",
            ))
            logger.warning("Constraint FAIL: %s.csv — %s", table_stem, detail_parts)

    return results


# ---------------------------------------------------------------------------
# Check 3: Relations — cross-table PID integrity (optional)
# ---------------------------------------------------------------------------

def check_relations(typed_dir: Path) -> List[CheckResult]:
    """Optional cross-table reference check.

    If both ``typed_process.csv`` and ``typed_net.csv`` exist, verify that
    every ``pid`` in the network table has a corresponding entry in the
    process table.
    """
    results: List[CheckResult] = []

    process_path = typed_dir / "typed_process.csv"
    net_path = typed_dir / "typed_net.csv"

    if not process_path.is_file() or not net_path.is_file():
        logger.debug(
            "Relational check skipped — need both typed_process.csv and typed_net.csv."
        )
        return results

    # Load process PIDs
    proc_table = read_csv_safe(process_path)
    try:
        pid_idx_proc = proc_table.headers.index("pid")
    except ValueError:
        logger.debug("typed_process.csv has no 'pid' column — skipping relational check.")
        return results

    process_pids: Set[str] = set()
    for row in proc_table.rows:
        if pid_idx_proc < len(row):
            val = row[pid_idx_proc].strip()
            if val:
                process_pids.add(val)

    # Load net PIDs
    net_table = read_csv_safe(net_path)
    try:
        pid_idx_net = net_table.headers.index("pid")
    except ValueError:
        logger.debug("typed_net.csv has no 'pid' column — skipping relational check.")
        return results

    orphan_pids: Set[str] = set()
    for row in net_table.rows:
        if pid_idx_net < len(row):
            val = row[pid_idx_net].strip()
            if val and val not in process_pids:
                orphan_pids.add(val)

    if not orphan_pids:
        results.append(CheckResult(
            table="net.csv → process.csv",
            check="relation",
            status="PASS",
            detail=(
                f"All PIDs in net.csv ({net_table.row_count} rows) "
                f"exist in process.csv ({proc_table.row_count} rows)."
            ),
        ))
        logger.info("Relation PASS: net.csv PIDs all found in process.csv.")
    else:
        results.append(CheckResult(
            table="net.csv → process.csv",
            check="relation",
            status="FAIL",
            detail=(
                f"{len(orphan_pids)} orphan PID(s) in net.csv not in process.csv: "
                f"{', '.join(sorted(orphan_pids)[:20])}"
                + (" …" if len(orphan_pids) > 20 else "")
            ),
        ))
        logger.warning(
            "Relation FAIL: %d orphan PID(s) in net.csv.", len(orphan_pids),
        )

    return results


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def write_validation_report(report: ValidationReport, path: Path) -> Path:
    """Write the validation report as a Markdown file.

    Parameters
    ----------
    report : ValidationReport
        The aggregated validation results.
    path : Path
        Destination file path.

    Returns
    -------
    Path
        The written file path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = [
        "# MemFlow Validation Report",
        "",
        f"**Generated:** {report.generated_at}  ",
        f"**Case:** {report.case_directory}  ",
        "",
        f"**Result:** {'FAIL' if report.has_failures else 'PASS'}  ",
        f"**Checks passed:** {report.pass_count}  ",
        f"**Checks failed:** {report.fail_count}  ",
        "",
        "---",
        "",
        "## Results",
        "",
        "| Table | Check | Status | Detail |",
        "|-------|-------|--------|--------|",
    ]

    for r in report.results:
        # Escape pipe characters in detail text for markdown tables
        safe_detail = r.detail.replace("|", "\\|")
        status_icon = "PASS" if r.status == "PASS" else "**FAIL**"
        lines.append(f"| {r.table} | {r.check} | {status_icon} | {safe_detail} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Generated by `memflow_validate` (MF-070).*")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Wrote validation report: %s", path)
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_validate",
        description=(
            "MF-070: Validate typed CSV outputs against the raw inventory "
            "to ensure zero data loss."
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
        type=Path,
        default=None,
        help="Directory containing typed_*.csv files (default: <case>/csv/).",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for the report (default: <case>/artifacts/).",
    )
    parser.add_argument(
        "--specs", "-s",
        type=Path,
        default=None,
        help="Directory containing YAML spec files (default: memflow_specs/).",
    )
    parser.add_argument(
        "--manifest", "-m",
        type=Path,
        default=None,
        help=(
            "Path to _inventory_manifest.csv "
            "(default: <case>/artifacts/_inventory_manifest.csv)."
        ),
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns 0 on PASS, 1 on any FAIL, 2 on fatal error."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # -- Logging ------------------------------------------------------------ #
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    case_dir: Path = args.case.resolve()
    typed_dir: Path = (args.in_path or (case_dir / "csv")).resolve()
    out_dir: Path = (args.out or (case_dir / "artifacts")).resolve()
    specs_dir: Path = (args.specs or Path("memflow_specs")).resolve()
    manifest_path: Path = (
        args.manifest or (case_dir / "artifacts" / "_inventory_manifest.csv")
    ).resolve()

    # -- Startup validation ------------------------------------------------- #
    if not case_dir.exists():
        logger.warning("Case directory does not exist, creating: %s", case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)

    if not typed_dir.is_dir():
        logger.error(
            "Typed CSV directory does not exist: %s", typed_dir,
        )
        return 2

    if not manifest_path.is_file():
        logger.error(
            "Manifest file not found: %s  — run memflow_inventory first.",
            manifest_path,
        )
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    # -- Load manifest ------------------------------------------------------ #
    manifest = load_manifest(manifest_path)
    if not manifest:
        logger.error("Manifest is empty or unreadable.")
        return 2

    # -- Run checks --------------------------------------------------------- #
    report = ValidationReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        case_directory=str(case_dir),
    )

    # 1. Parity
    report.results.extend(check_parity(manifest, typed_dir))

    # 2. Constraints (only if specs directory exists)
    if specs_dir.is_dir():
        report.results.extend(check_constraints(typed_dir, specs_dir))
    else:
        logger.warning(
            "Specs directory not found (%s) — skipping constraint checks.",
            specs_dir,
        )

    # 3. Relations (optional, auto-detected)
    report.results.extend(check_relations(typed_dir))

    # -- Write report ------------------------------------------------------- #
    report_path = out_dir / "validation_report.md"
    write_validation_report(report, report_path)

    # -- Summary ------------------------------------------------------------ #
    logger.info(
        "Validation complete: %d check(s), %d PASS, %d FAIL.",
        len(report.results),
        report.pass_count,
        report.fail_count,
    )

    if report.has_failures:
        logger.warning("VALIDATION FAILED — see %s", report_path)
        return 1

    logger.info("ALL CHECKS PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

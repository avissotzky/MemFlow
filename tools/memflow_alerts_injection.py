"""
tools.memflow_alerts_injection
===============================
**MF-102 — Process Injection / Rootkit Alerting (The Ghost Hunter).**

Detects code running where it shouldn't — the hallmarks of fileless malware,
process hollowing, rootkits, and reflective DLL injection.

Data sources:

1. ``typed_findevil.csv`` — MemProcFS *FindEvil* output (preferred).
2. ``typed_vad.csv`` — Virtual Address Descriptor dump (fallback).
3. ``typed_process.csv`` — Active process list (for DKOM cross-reference).

Detection rules:

1. **RWX_UNBACKED** — ``PAGE_EXECUTE_READWRITE`` region that is *Private*
   (not backed by a file on disk).  The #1 indicator of shellcode injection.
   Severity: **Critical**.
2. **PROCESS_HOLLOWING** — Known process name (e.g. ``svchost.exe``) has a
   VAD *Image* section that points to a different path or is empty.
   Severity: **Critical**.
3. **DKOM_HIDDEN_PROCESS** — PID found in ``findevil.csv`` (pool-tag scan)
   but absent from ``typed_process.csv`` (ActiveProcessLinks).  Rootkit
   activity.  Severity: **Critical**.
4. **REFLECTIVE_DLL** — VAD region contains an MZ header but has no file
   path associated.  Severity: **High**.

Outputs
-------
- ``<case>/csv/alerts_injection.csv`` — One row per suspicious region.

Usage
-----
::

    python -m tools.memflow_alerts_injection --case C:\\Cases\\IR-2025-042

    python -m tools.memflow_alerts_injection \
        --case ./case1 \
        --in   ./case1/csv \
        --out  ./case1/csv
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe
from memflow_rules import load_ruleset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — loaded from memflow_rules/injection.json
# ---------------------------------------------------------------------------

_rules = load_ruleset("injection")

_RWX_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in _rules["rwx_patterns"]
]
_UNBACKED_SENTINELS: Set[str] = set(_rules["unbacked_sentinels"])
_HOLLOWING_TARGETS: Set[str] = set(_rules["hollowing_targets"])
_EXPECTED_PATHS: Dict[str, str] = _rules["expected_paths"]

del _rules

#: Alert-type tags.
_ALERT_RWX_UNBACKED = "RWX_UNBACKED"
_ALERT_PROCESS_HOLLOWING = "PROCESS_HOLLOWING"
_ALERT_DKOM = "DKOM_HIDDEN_PROCESS"
_ALERT_REFLECTIVE_DLL = "REFLECTIVE_DLL"

#: Output CSV headers.
_OUTPUT_HEADERS: List[str] = [
    "alert_type",
    "severity",
    "pid",
    "process_name",
    "address",
    "size",
    "protection",
    "backing_file",
    "source_table",
    "description",
]


# ---------------------------------------------------------------------------
# Column-name resolution helpers
# ---------------------------------------------------------------------------

def _find_column(headers: List[str], candidates: List[str]) -> Optional[int]:
    """Return the index of the first matching header (case-insensitive)."""
    lower_headers = [h.lower().strip() for h in headers]
    for candidate in candidates:
        if candidate.lower() in lower_headers:
            return lower_headers.index(candidate.lower())
    return None


def _resolve_memory_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a memory-region table.

    Works for both ``findevil.csv`` and ``vad.csv`` — the candidate lists
    cover naming variants from MemProcFS.
    """
    return {
        "pid":        _find_column(headers, [
            "pid", "process_id",
        ]),
        "name":       _find_column(headers, [
            "name", "process_name", "process", "image", "image_name",
        ]),
        "address":    _find_column(headers, [
            "address", "addr", "va", "va-start", "start",
            "start_address", "base", "base_address",
        ]),
        "size":       _find_column(headers, [
            "size", "region_size", "region-size", "length", "cb",
        ]),
        "protection": _find_column(headers, [
            "protection", "prot", "protect", "flags",
            "page_protection", "page-protection",
        ]),
        "file":       _find_column(headers, [
            "file", "filename", "file_name", "filepath", "file_path",
            "path", "module", "backed_by", "description", "desc",
            "tag", "info",
        ]),
        "type":       _find_column(headers, [
            "type", "region_type", "vadtype", "vad_type",
        ]),
    }


def _resolve_process_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a process table."""
    return {
        "pid":  _find_column(headers, ["pid", "process_id"]),
        "name": _find_column(headers, ["name", "process_name", "image",
                                       "image_name", "imagename"]),
        "path": _find_column(headers, ["path", "image_path", "filepath",
                                       "file_path", "full_path"]),
    }


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _is_rwx(protection: str) -> bool:
    """Return ``True`` if *protection* indicates Read-Write-Execute."""
    if not protection:
        return False
    for pattern in _RWX_PATTERNS:
        if pattern.search(protection):
            return True
    return False


def _is_unbacked(file_value: str) -> bool:
    """Return ``True`` if *file_value* indicates the region is not backed by disk."""
    return file_value.strip().lower() in _UNBACKED_SENTINELS


def _cell(row: List[str], idx: Optional[int]) -> str:
    """Safely extract a cell value."""
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


def _looks_like_mz_header(value: str) -> bool:
    """Return ``True`` if *value* suggests the region contains an MZ header.

    Checks for common indicators in MemProcFS output that a memory region
    starts with the DOS MZ stub (Windows PE header).
    """
    val_lower = value.lower().strip()
    if not val_lower:
        return False
    # MemProcFS may put "MZ" or "4d5a" (hex) or "PE" markers in tag/desc
    return (
        val_lower.startswith("mz")
        or "4d5a" in val_lower          # MZ in hex
        or val_lower.startswith("pe")
        or "mz header" in val_lower
        or "pe header" in val_lower
        or "executable" in val_lower
    )


# ---------------------------------------------------------------------------
# Core alert logic: Rule 1 — RWX Unbacked (Floating Code)
# ---------------------------------------------------------------------------

def _detect_rwx_unbacked(
    table: RawTable,
    source_name: str,
    cols: Dict[str, Optional[int]],
) -> List[List[str]]:
    """Detect RWX regions not backed by a file on disk."""
    prot_idx = cols["protection"]
    if prot_idx is None:
        logger.error(
            "%s has no recognisable 'protection' column — "
            "cannot detect RWX regions.",
            source_name,
        )
        return []

    file_idx = cols["file"]
    type_idx = cols["type"]
    rows: List[List[str]] = []
    rwx_count = 0

    for row in table.rows:
        protection = _cell(row, prot_idx)
        if not _is_rwx(protection):
            continue
        rwx_count += 1

        file_val = _cell(row, file_idx)
        type_val = _cell(row, type_idx).lower()

        # Check: RWX + unbacked (private / no file)
        is_private = "private" in type_val if type_val else True
        if not _is_unbacked(file_val) and not is_private:
            continue

        pid_val = _cell(row, cols["pid"])
        proc_name = _cell(row, cols["name"])
        address = _cell(row, cols["address"])
        size = _cell(row, cols["size"])

        rows.append([
            _ALERT_RWX_UNBACKED,
            "CRITICAL",
            pid_val,
            proc_name,
            address,
            size,
            protection,
            file_val if file_val else "<none>",
            source_name,
            (
                f"RWX memory region at {address or '?'} "
                f"(size {size or '?'}) in PID {pid_val or '?'}"
                + (f" ({proc_name})" if proc_name else "")
                + " is not backed by a file on disk. "
                + "Top indicator of shellcode injection (Cobalt Strike, Meterpreter)."
            ),
        ])

    logger.info(
        "RWX scan of %s: %d total rows, %d RWX, %d unbacked alerts.",
        source_name, table.row_count, rwx_count, len(rows),
    )
    return rows


# ---------------------------------------------------------------------------
# Core alert logic: Rule 2 — Process Hollowing
# ---------------------------------------------------------------------------

def _detect_process_hollowing(
    table: RawTable,
    source_name: str,
    cols: Dict[str, Optional[int]],
) -> List[List[str]]:
    """Detect process hollowing: known process with Image section pointing elsewhere."""
    name_idx = cols["name"]
    file_idx = cols["file"]
    type_idx = cols["type"]

    if name_idx is None:
        logger.warning("Cannot check process hollowing — no 'name' column in %s.", source_name)
        return []

    rows: List[List[str]] = []

    for row in table.rows:
        proc_name = _cell(row, name_idx)
        proc_lower = proc_name.lower()

        if proc_lower not in _HOLLOWING_TARGETS:
            continue

        # Only interested in Image-type sections
        type_val = _cell(row, type_idx).lower()
        if type_val and "image" not in type_val:
            continue

        file_val = _cell(row, file_idx).lower()
        expected_path = _EXPECTED_PATHS.get(proc_lower, "")

        # Hollowing: Image section with empty path or path mismatch
        is_empty = _is_unbacked(file_val)
        is_mismatch = (
            expected_path
            and file_val
            and not is_empty
            and not file_val.startswith(expected_path)
        )

        if is_empty or is_mismatch:
            pid_val = _cell(row, cols["pid"])
            address = _cell(row, cols["address"])
            size = _cell(row, cols["size"])
            protection = _cell(row, cols["protection"])

            reason = (
                f"empty/missing backing file"
                if is_empty
                else f"path mismatch (expected '{expected_path}', got '{file_val}')"
            )

            rows.append([
                _ALERT_PROCESS_HOLLOWING,
                "CRITICAL",
                pid_val,
                proc_name,
                address,
                size,
                protection,
                file_val if file_val else "<none>",
                source_name,
                (
                    f"Suspected process hollowing: '{proc_name}' (PID {pid_val or '?'}) "
                    f"has Image section with {reason}."
                ),
            ])

    logger.info(
        "Process hollowing scan of %s: %d alert(s).", source_name, len(rows),
    )
    return rows


# ---------------------------------------------------------------------------
# Core alert logic: Rule 3 — DKOM (Hidden Processes)
# ---------------------------------------------------------------------------

def detect_dkom(
    mem_table: RawTable,
    proc_table: RawTable,
    mem_source: str,
) -> List[List[str]]:
    """Detect DKOM: PIDs in findevil/vad but not in typed_process.csv.

    Parameters
    ----------
    mem_table : RawTable
        Memory-region table (findevil or vad).
    proc_table : RawTable
        Active process table.
    mem_source : str
        Friendly name for the memory-region source.

    Returns
    -------
    list
        Alert rows.
    """
    # Build set of active PIDs from process table.
    proc_cols = _resolve_process_columns(proc_table.headers)
    proc_pid_idx = proc_cols["pid"]
    if proc_pid_idx is None:
        logger.warning("Cannot check DKOM — no 'pid' column in typed_process.csv.")
        return []

    active_pids: Set[str] = set()
    for row in proc_table.rows:
        pid_val = _cell(row, proc_pid_idx)
        if pid_val:
            active_pids.add(pid_val)

    # Scan memory table for PIDs absent from active set.
    mem_cols = _resolve_memory_columns(mem_table.headers)
    mem_pid_idx = mem_cols["pid"]
    if mem_pid_idx is None:
        logger.warning("Cannot check DKOM — no 'pid' column in %s.", mem_source)
        return []

    seen_hidden: Set[str] = set()
    rows: List[List[str]] = []

    for row in mem_table.rows:
        pid_val = _cell(row, mem_pid_idx)
        if not pid_val or pid_val in active_pids or pid_val in seen_hidden:
            continue
        # Skip PID 0 / 4 (System / Idle) — they appear differently.
        if pid_val in ("0", "4"):
            continue

        seen_hidden.add(pid_val)
        proc_name = _cell(row, mem_cols["name"])
        address = _cell(row, mem_cols["address"])

        rows.append([
            _ALERT_DKOM,
            "CRITICAL",
            pid_val,
            proc_name if proc_name else "<hidden>",
            address,
            "",                         # size
            "",                         # protection
            "",                         # backing_file
            mem_source,
            (
                f"PID {pid_val}"
                + (f" ({proc_name})" if proc_name else "")
                + f" exists in {mem_source} (pool-tag scan) but NOT in "
                + "typed_process.csv (ActiveProcessLinks). "
                + "Possible rootkit DKOM manipulation."
            ),
        ])

    logger.info("DKOM scan: %d hidden PID(s) detected.", len(rows))
    return rows


# ---------------------------------------------------------------------------
# Core alert logic: Rule 4 — Reflective DLL Loading
# ---------------------------------------------------------------------------

def _detect_reflective_dll(
    table: RawTable,
    source_name: str,
    cols: Dict[str, Optional[int]],
) -> List[List[str]]:
    """Detect reflective DLL: MZ header in VAD region with no file path."""
    file_idx = cols["file"]
    type_idx = cols["type"]

    rows: List[List[str]] = []

    for row in table.rows:
        file_val = _cell(row, file_idx)
        type_val = _cell(row, type_idx)

        # Look for MZ header indicator in the type/tag/file columns
        # combined with no legitimate backing file path.
        has_mz = _looks_like_mz_header(type_val) or _looks_like_mz_header(file_val)

        # The file path should look like a sentinel (empty / n/a)
        # OR the MZ indicator is in the type/tag field while path is empty.
        is_pathless = _is_unbacked(file_val)

        # MZ header detected but in a file-backed location → not reflective
        if has_mz and is_pathless:
            pid_val = _cell(row, cols["pid"])
            proc_name = _cell(row, cols["name"])
            address = _cell(row, cols["address"])
            size = _cell(row, cols["size"])
            protection = _cell(row, cols["protection"])

            rows.append([
                _ALERT_REFLECTIVE_DLL,
                "HIGH",
                pid_val,
                proc_name,
                address,
                size,
                protection,
                "<none>",
                source_name,
                (
                    f"Memory region at {address or '?'} in PID {pid_val or '?'}"
                    + (f" ({proc_name})" if proc_name else "")
                    + " contains MZ header (Windows executable) but has no "
                    + "associated file path. Possible reflective DLL injection."
                ),
            ])

    logger.info(
        "Reflective DLL scan of %s: %d alert(s).", source_name, len(rows),
    )
    return rows


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_injection_alerts(
    mem_table: RawTable,
    proc_table: Optional[RawTable],
    source_name: str,
) -> RawTable:
    """Run all injection detection rules and return combined alerts.

    Parameters
    ----------
    mem_table : RawTable
        The ``typed_findevil.csv`` or ``typed_vad.csv`` table.
    proc_table : RawTable or None
        The ``typed_process.csv`` table (needed for DKOM).
    source_name : str
        Friendly name of the memory source table.

    Returns
    -------
    RawTable
        Combined alert table.
    """
    cols = _resolve_memory_columns(mem_table.headers)
    alerts = RawTable(headers=list(_OUTPUT_HEADERS))

    # Rule 1: RWX Unbacked (Floating Code)
    alerts.rows.extend(_detect_rwx_unbacked(mem_table, source_name, cols))

    # Rule 2: Process Hollowing
    alerts.rows.extend(_detect_process_hollowing(mem_table, source_name, cols))

    # Rule 3: DKOM (Hidden Processes)
    if proc_table is not None:
        alerts.rows.extend(detect_dkom(mem_table, proc_table, source_name))
    else:
        logger.warning("typed_process.csv not available — DKOM check skipped.")

    # Rule 4: Reflective DLL Loading
    alerts.rows.extend(_detect_reflective_dll(mem_table, source_name, cols))

    logger.info(
        "Injection scan complete (%s): %d total alert(s).",
        source_name, alerts.row_count,
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_alerts_injection",
        description=(
            "MF-102: Detect process injection, rootkits, and reflective DLL "
            "loading from memory-region CSVs."
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
        help=(
            "Directory containing typed_findevil.csv or typed_vad.csv "
            "(default: <case>/csv/)."
        ),
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for alerts_injection.csv (default: <case>/csv/).",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns 0 if no alerts, 1 if alerts found, 2 on fatal."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # -- Logging ------------------------------------------------------------ #
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    case_dir: Path = args.case.resolve()
    in_dir: Path = (args.in_path or (case_dir / "csv")).resolve()
    out_dir: Path = (args.out or (case_dir / "csv")).resolve()

    # -- Startup validation ------------------------------------------------- #
    if not case_dir.exists():
        logger.warning("Case directory does not exist, creating: %s", case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)

    if not in_dir.is_dir():
        logger.error("Input directory does not exist: %s", in_dir)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    # -- Locate a memory-region CSV (prefer findevil, fall back to vad) ----- #
    findevil_path = in_dir / "typed_findevil.csv"
    vad_path = in_dir / "typed_vad.csv"

    source_path: Optional[Path] = None
    source_name: str = ""

    if findevil_path.is_file():
        source_path = findevil_path
        source_name = "typed_findevil.csv"
        logger.info("Using FindEvil data: %s", source_path)
    elif vad_path.is_file():
        source_path = vad_path
        source_name = "typed_vad.csv"
        logger.info("FindEvil not found; falling back to VAD data: %s", source_path)
    else:
        logger.error(
            "Neither typed_findevil.csv nor typed_vad.csv found in %s. "
            "Cannot run injection alerting.",
            in_dir,
        )
        return 2

    # -- Load tables -------------------------------------------------------- #
    mem_table = read_csv_safe(source_path)

    proc_table: Optional[RawTable] = None
    proc_path = in_dir / "typed_process.csv"
    if proc_path.is_file():
        proc_table = read_csv_safe(proc_path)
    else:
        logger.warning(
            "typed_process.csv not found — DKOM detection will be skipped."
        )

    if mem_table.row_count == 0:
        logger.warning("%s has no data rows — nothing to analyse.", source_name)
        write_csv_safe(
            RawTable(headers=list(_OUTPUT_HEADERS)),
            out_dir / "alerts_injection.csv",
        )
        return 0

    # -- Generate alerts ---------------------------------------------------- #
    alerts = generate_injection_alerts(mem_table, proc_table, source_name)

    # -- Write output ------------------------------------------------------- #
    out_path = out_dir / "alerts_injection.csv"
    write_csv_safe(alerts, out_path)

    # -- Summary & exit code ------------------------------------------------ #
    logger.info(
        "Injection alerting complete: %d alert(s) written to %s",
        alerts.row_count,
        out_path,
    )

    return 1 if alerts.row_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

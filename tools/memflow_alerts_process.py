"""
tools.memflow_alerts_process
=============================
**MF-103 — Masquerading & Process Anomaly Alerting (The Imposter Hunter).**

Detects malware pretending to be legitimate Windows processes by analysing
process names, paths, parent-child relationships, and user context.

Input: ``typed_process.csv``.
Output: ``<case>/csv/alerts_process.csv``.

Detection rules:

1. **PATH_MASQUERADE** — System binary (``svchost.exe``, ``csrss.exe``,
   ``lsass.exe``) running from outside ``C:\\Windows\\System32\\``.
   Severity: **High**.
2. **PARENT_CHILD_MISMATCH** — Unexpected parent for a given child process
   (e.g. ``svchost.exe`` not spawned by ``services.exe``, or Office apps
   spawning ``cmd.exe`` / ``powershell.exe``).  Severity: **High**.
3. **TYPOSQUATTING** — Process name has Levenshtein distance < 2 to a
   critical system name (e.g. ``scvhost.exe``, ``lsas.exe``).
   Severity: **Medium**.
4. **SID_MISMATCH** — ``lsass.exe`` or ``csrss.exe`` running as a
   non-SYSTEM user.  Severity: **High**.

Usage
-----
::

    python -m tools.memflow_alerts_process --case C:\\Cases\\IR-2025-042

    python -m tools.memflow_alerts_process \\
        --case ./case1 \\
        --in   ./case1/csv \\
        --out  ./case1/csv
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe
from memflow_rules import load_ruleset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — loaded from memflow_rules/process.json
# ---------------------------------------------------------------------------

_rules = load_ruleset("process")

_SYSTEM32_ONLY: Set[str] = set(_rules["system32_only"])
_SYSTEM32_PREFIXES = tuple(_rules["system32_prefixes"])
_PARENT_RULES: Dict[str, Set[str]] = {
    k: set(v) for k, v in _rules["parent_rules"].items()
}
_SHELL_CHILDREN: Set[str] = set(_rules["shell_children"])
_OFFICE_PARENTS: Set[str] = set(_rules["office_parents"])
_CRITICAL_NAMES: List[str] = list(_rules["critical_names"])
_SYSTEM_ONLY_PROCESSES: Set[str] = set(_rules["system_only_processes"])
_SYSTEM_USER_MARKERS: Set[str] = set(_rules["system_user_markers"])

del _rules

#: Alert-type tags.
_ALERT_PATH_MASQUERADE = "PATH_MASQUERADE"
_ALERT_PARENT_CHILD = "PARENT_CHILD_MISMATCH"
_ALERT_TYPOSQUATTING = "TYPOSQUATTING"
_ALERT_SID_MISMATCH = "SID_MISMATCH"

#: Output CSV headers.
_OUTPUT_HEADERS: List[str] = [
    "alert_type",
    "severity",
    "pid",
    "process_name",
    "process_path",
    "ppid",
    "parent_name",
    "user",
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


def _resolve_process_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a process table."""
    return {
        "pid":         _find_column(headers, ["pid", "process_id"]),
        "name":        _find_column(headers, ["name", "process_name", "image",
                                              "image_name", "imagename"]),
        "path":        _find_column(headers, ["path", "image_path", "filepath",
                                              "file_path", "full_path",
                                              "process_path"]),
        "ppid":        _find_column(headers, ["ppid", "parent_pid",
                                              "parent_process_id",
                                              "inheritedfrompid"]),
        "parent_name": _find_column(headers, ["parent_name", "parent_process",
                                              "parent_image", "parent"]),
        "user":        _find_column(headers, ["user", "username", "user_name",
                                              "sid", "owner", "account",
                                              "user_sid"]),
        "cmdline":     _find_column(headers, ["cmdline", "commandline",
                                              "command_line", "cmd"]),
    }


def _cell(row: List[str], idx: Optional[int]) -> str:
    """Safely extract a cell value."""
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


# ---------------------------------------------------------------------------
# Levenshtein distance (stdlib-only, no external deps)
# ---------------------------------------------------------------------------

def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (0 if c1 == c2 else 1)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ---------------------------------------------------------------------------
# PID → name lookup for parent resolution
# ---------------------------------------------------------------------------

def _build_pid_name_lookup(
    proc_table: RawTable,
    cols: Dict[str, Optional[int]],
) -> Dict[str, str]:
    """Build {pid: process_name} mapping."""
    pid_idx = cols["pid"]
    name_idx = cols["name"]
    if pid_idx is None or name_idx is None:
        return {}
    lookup: Dict[str, str] = {}
    for row in proc_table.rows:
        pid_val = _cell(row, pid_idx)
        name_val = _cell(row, name_idx)
        if pid_val:
            lookup[pid_val] = name_val
    return lookup


# ---------------------------------------------------------------------------
# Core alert logic
# ---------------------------------------------------------------------------

def generate_process_alerts(proc_table: RawTable) -> RawTable:
    """Run all process-masquerading detection rules.

    Parameters
    ----------
    proc_table : RawTable
        The ``typed_process.csv`` table.

    Returns
    -------
    RawTable
        Alert table ready for ``write_csv_safe``.
    """
    cols = _resolve_process_columns(proc_table.headers)
    pid_idx = cols["pid"]
    name_idx = cols["name"]

    if pid_idx is None or name_idx is None:
        logger.error(
            "typed_process.csv missing critical columns (pid/name). "
            "Cannot run masquerading checks."
        )
        return RawTable(headers=list(_OUTPUT_HEADERS))

    pid_name_map = _build_pid_name_lookup(proc_table, cols)
    alerts = RawTable(headers=list(_OUTPUT_HEADERS))

    for row in proc_table.rows:
        pid_val = _cell(row, pid_idx)
        name_val = _cell(row, name_idx)
        name_lower = name_val.lower()
        path_val = _cell(row, cols["path"])
        path_lower = path_val.lower()
        ppid_val = _cell(row, cols["ppid"])
        parent_name_raw = _cell(row, cols["parent_name"])
        user_val = _cell(row, cols["user"])
        user_lower = user_val.lower()

        # Resolve parent name: prefer explicit column, fall back to PID lookup.
        parent_name = parent_name_raw if parent_name_raw else pid_name_map.get(ppid_val, "")
        parent_lower = parent_name.lower()

        # ---- Rule 1: Path Masquerading ------------------------------------
        if name_lower in _SYSTEM32_ONLY and path_val:
            if not any(path_lower.startswith(p) for p in _SYSTEM32_PREFIXES):
                alerts.rows.append([
                    _ALERT_PATH_MASQUERADE,
                    "HIGH",
                    pid_val,
                    name_val,
                    path_val,
                    ppid_val,
                    parent_name,
                    user_val,
                    (
                        f"'{name_val}' (PID {pid_val}) running from '{path_val}' "
                        f"instead of System32. System binaries never run from "
                        f"Temp, Downloads, or user directories."
                    ),
                ])

        # ---- Rule 2: Parent-Child Mismatch --------------------------------
        # 2a: svchost.exe must be spawned by services.exe
        if name_lower in _PARENT_RULES and parent_name:
            expected_parents = _PARENT_RULES[name_lower]
            if parent_lower not in expected_parents:
                alerts.rows.append([
                    _ALERT_PARENT_CHILD,
                    "HIGH",
                    pid_val,
                    name_val,
                    path_val,
                    ppid_val,
                    parent_name,
                    user_val,
                    (
                        f"'{name_val}' (PID {pid_val}) spawned by "
                        f"'{parent_name}' (PPID {ppid_val}), expected "
                        f"{sorted(expected_parents)}."
                    ),
                ])

        # 2b: Office apps spawning shells (Macro Malware)
        if name_lower in _SHELL_CHILDREN and parent_lower in _OFFICE_PARENTS:
            alerts.rows.append([
                _ALERT_PARENT_CHILD,
                "HIGH",
                pid_val,
                name_val,
                path_val,
                ppid_val,
                parent_name,
                user_val,
                (
                    f"Shell '{name_val}' (PID {pid_val}) spawned by Office "
                    f"process '{parent_name}' (PPID {ppid_val}). "
                    f"Classic macro malware indicator."
                ),
            ])

        # ---- Rule 3: Typosquatting ----------------------------------------
        if name_lower not in {n.lower() for n in _CRITICAL_NAMES}:
            for critical in _CRITICAL_NAMES:
                dist = _levenshtein(name_lower, critical.lower())
                if 0 < dist < 2:
                    alerts.rows.append([
                        _ALERT_TYPOSQUATTING,
                        "MEDIUM",
                        pid_val,
                        name_val,
                        path_val,
                        ppid_val,
                        parent_name,
                        user_val,
                        (
                            f"'{name_val}' (PID {pid_val}) is suspiciously "
                            f"similar to '{critical}' (edit distance {dist}). "
                            f"Possible typosquatting."
                        ),
                    ])
                    break  # One alert per process is enough.

        # ---- Rule 4: SID / User Context Mismatch -------------------------
        if name_lower in _SYSTEM_ONLY_PROCESSES and user_val:
            is_system = any(
                marker in user_lower for marker in _SYSTEM_USER_MARKERS
            )
            if not is_system:
                alerts.rows.append([
                    _ALERT_SID_MISMATCH,
                    "HIGH",
                    pid_val,
                    name_val,
                    path_val,
                    ppid_val,
                    parent_name,
                    user_val,
                    (
                        f"'{name_val}' (PID {pid_val}) running as user "
                        f"'{user_val}' instead of SYSTEM. Critical system "
                        f"processes must run under NT AUTHORITY\\SYSTEM."
                    ),
                ])

    logger.info(
        "Process masquerading scan complete: %d alert(s) from %d process(es).",
        alerts.row_count,
        proc_table.row_count,
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_alerts_process",
        description=(
            "MF-103: Detect masquerading, parent-child mismatches, "
            "typosquatting, and SID anomalies in typed_process.csv."
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
        help="Directory containing typed_process.csv (default: <case>/csv/).",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for alerts_process.csv (default: <case>/csv/).",
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

    # -- Locate required CSV ------------------------------------------------ #
    proc_path = in_dir / "typed_process.csv"

    if not proc_path.is_file():
        logger.error("Required file not found: %s", proc_path)
        return 2

    # -- Load table --------------------------------------------------------- #
    proc_table = read_csv_safe(proc_path)

    if proc_table.row_count == 0:
        logger.warning("typed_process.csv has no data rows — nothing to analyse.")
        write_csv_safe(
            RawTable(headers=list(_OUTPUT_HEADERS)),
            out_dir / "alerts_process.csv",
        )
        return 0

    # -- Generate alerts ---------------------------------------------------- #
    alerts = generate_process_alerts(proc_table)

    # -- Write output ------------------------------------------------------- #
    out_path = out_dir / "alerts_process.csv"
    write_csv_safe(alerts, out_path)

    # -- Summary & exit code ------------------------------------------------ #
    logger.info(
        "Process alerting complete: %d alert(s) written to %s",
        alerts.row_count,
        out_path,
    )

    return 1 if alerts.row_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

"""
tools.memflow_alerts_persistence
=================================
**MF-104 — Persistence Mechanism Alerting (The Tick Hunter).**

Detects how malware survives a reboot by analysing registry Run keys,
services, and scheduled tasks.

Inputs:

- ``typed_registry.csv`` — Registry hive entries (Run / RunOnce keys).
- ``typed_services.csv`` — Windows services.
- ``typed_tasks.csv`` — Scheduled tasks.

Output: ``<case>/csv/alerts_persistence.csv``.

Detection rules:

1. **SUSPICIOUS_RUN_KEY** — Registry ``Run`` or ``RunOnce`` path where the
   value data points to ``%TEMP%``, ``%APPDATA%``, or a ``Users`` folder.
   Severity: **High**.
2. **SERVICE_MASQUERADE** — Service binary path contains ``powershell`` or
   ``cmd``.  Severity: **High**.
3. **HIDDEN_SCHEDULED_TASK** — Task action starts with ``cmd /c`` or
   ``powershell -w hidden``.  Severity: **Medium**.

Usage
-----
::

    python -m tools.memflow_alerts_persistence --case C:\\Cases\\IR-2025-042

    python -m tools.memflow_alerts_persistence \\
        --case ./case1 \\
        --in   ./case1/csv \\
        --out  ./case1/csv
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe
from memflow_rules import load_ruleset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — loaded from memflow_rules/persistence.json
# ---------------------------------------------------------------------------

#: Alert-type tags.
_ALERT_SUSPICIOUS_RUN_KEY = "SUSPICIOUS_RUN_KEY"
_ALERT_SERVICE_MASQUERADE = "SERVICE_MASQUERADE"
_ALERT_HIDDEN_SCHED_TASK = "HIDDEN_SCHEDULED_TASK"

#: Output CSV headers.
_OUTPUT_HEADERS: List[str] = [
    "alert_type",
    "severity",
    "source_table",
    "key_or_name",
    "value_or_path",
    "description",
]

_rules = load_ruleset("persistence")

_RUN_KEY_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in _rules["run_key_patterns"]
]
_SUSPICIOUS_RUN_PATHS = tuple(_rules["suspicious_run_paths"])
_SERVICE_SUSPICIOUS = tuple(_rules["service_suspicious"])
_TASK_SUSPICIOUS_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in _rules["task_suspicious_patterns"]
]

del _rules


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


def _resolve_registry_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a registry table."""
    return {
        "path": _find_column(headers, [
            "path", "key", "key_path", "registry_path", "reg_path",
            "hive_path", "keypath",
        ]),
        "name": _find_column(headers, [
            "name", "value_name", "valuename", "entry", "value",
        ]),
        "data": _find_column(headers, [
            "data", "value_data", "valuedata", "content", "value_content",
        ]),
        "type": _find_column(headers, [
            "type", "value_type", "reg_type", "datatype",
        ]),
    }


def _resolve_service_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a services table."""
    return {
        "name": _find_column(headers, [
            "name", "service_name", "servicename", "display_name",
        ]),
        "binary_path": _find_column(headers, [
            "binary_path", "binarypath", "image_path", "imagepath",
            "path", "binary", "pathname", "command", "cmdline",
        ]),
        "start_type": _find_column(headers, [
            "start_type", "starttype", "start", "startup",
        ]),
        "state": _find_column(headers, [
            "state", "status", "current_state",
        ]),
    }


def _resolve_task_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a scheduled-tasks table."""
    return {
        "name": _find_column(headers, [
            "name", "task_name", "taskname",
        ]),
        "action": _find_column(headers, [
            "action", "actions", "command", "cmdline", "exec",
            "task_action", "execute", "program",
        ]),
        "trigger": _find_column(headers, [
            "trigger", "triggers", "schedule", "next_run",
        ]),
        "status": _find_column(headers, [
            "status", "state", "enabled",
        ]),
    }


def _cell(row: List[str], idx: Optional[int]) -> str:
    """Safely extract a cell value."""
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


# ---------------------------------------------------------------------------
# Rule 1: Suspicious Run Keys
# ---------------------------------------------------------------------------

def _detect_run_keys(reg_table: RawTable) -> List[List[str]]:
    """Flag Run/RunOnce entries pointing to user-writable locations."""
    cols = _resolve_registry_columns(reg_table.headers)
    path_idx = cols["path"]
    data_idx = cols["data"]
    name_idx = cols["name"]

    if path_idx is None:
        logger.warning("typed_registry.csv has no 'path'/'key' column — skipping Run key check.")
        return []

    rows: List[List[str]] = []

    for row in reg_table.rows:
        reg_path = _cell(row, path_idx)
        reg_path_lower = reg_path.lower()

        # Is this a Run / RunOnce key?
        is_run_key = any(p.search(reg_path) for p in _RUN_KEY_PATTERNS)
        if not is_run_key:
            continue

        data_val = _cell(row, data_idx)
        data_lower = data_val.lower()
        name_val = _cell(row, name_idx)

        # Check if value data points to suspicious paths.
        for marker in _SUSPICIOUS_RUN_PATHS:
            if marker in data_lower:
                rows.append([
                    _ALERT_SUSPICIOUS_RUN_KEY,
                    "HIGH",
                    "typed_registry.csv",
                    f"{reg_path} :: {name_val}",
                    data_val,
                    (
                        f"Run key '{name_val}' under '{reg_path}' points to "
                        f"'{data_val}'. User-writable location is suspicious "
                        f"for persistence."
                    ),
                ])
                break  # One alert per entry.

    logger.info("Run-key scan: %d alert(s) from %d registry entries.",
                len(rows), reg_table.row_count)
    return rows


# ---------------------------------------------------------------------------
# Rule 2: Service Masquerading
# ---------------------------------------------------------------------------

def _detect_service_masquerade(svc_table: RawTable) -> List[List[str]]:
    """Flag services whose binary path contains suspicious interpreters."""
    cols = _resolve_service_columns(svc_table.headers)
    name_idx = cols["name"]
    bin_idx = cols["binary_path"]

    if bin_idx is None:
        logger.warning("typed_services.csv has no 'binary_path' column — skipping.")
        return []

    rows: List[List[str]] = []

    for row in svc_table.rows:
        svc_name = _cell(row, name_idx)
        bin_path = _cell(row, bin_idx)
        bin_lower = bin_path.lower()

        for marker in _SERVICE_SUSPICIOUS:
            if marker in bin_lower:
                rows.append([
                    _ALERT_SERVICE_MASQUERADE,
                    "HIGH",
                    "typed_services.csv",
                    svc_name,
                    bin_path,
                    (
                        f"Service '{svc_name}' has binary path '{bin_path}' "
                        f"containing '{marker}'. Legitimate services rarely "
                        f"invoke script interpreters directly."
                    ),
                ])
                break

    logger.info("Service masquerade scan: %d alert(s) from %d services.",
                len(rows), svc_table.row_count)
    return rows


# ---------------------------------------------------------------------------
# Rule 3: Hidden Scheduled Tasks
# ---------------------------------------------------------------------------

def _detect_hidden_tasks(task_table: RawTable) -> List[List[str]]:
    """Flag scheduled tasks with hidden / encoded execution actions."""
    cols = _resolve_task_columns(task_table.headers)
    name_idx = cols["name"]
    action_idx = cols["action"]

    if action_idx is None:
        logger.warning("typed_tasks.csv has no 'action' column — skipping.")
        return []

    rows: List[List[str]] = []

    for row in task_table.rows:
        task_name = _cell(row, name_idx)
        action = _cell(row, action_idx)

        for pattern in _TASK_SUSPICIOUS_PATTERNS:
            if pattern.search(action):
                rows.append([
                    _ALERT_HIDDEN_SCHED_TASK,
                    "MEDIUM",
                    "typed_tasks.csv",
                    task_name,
                    action,
                    (
                        f"Scheduled task '{task_name}' has suspicious action: "
                        f"'{action}'. Hidden/encoded execution is a common "
                        f"persistence technique."
                    ),
                ])
                break

    logger.info("Scheduled-task scan: %d alert(s) from %d tasks.",
                len(rows), task_table.row_count)
    return rows


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_persistence_alerts(
    reg_table: Optional[RawTable],
    svc_table: Optional[RawTable],
    task_table: Optional[RawTable],
) -> RawTable:
    """Run all persistence detection rules and return combined alerts.

    Parameters
    ----------
    reg_table : RawTable or None
        The ``typed_registry.csv`` table.
    svc_table : RawTable or None
        The ``typed_services.csv`` table.
    task_table : RawTable or None
        The ``typed_tasks.csv`` table.

    Returns
    -------
    RawTable
        Combined alert table.
    """
    alerts = RawTable(headers=list(_OUTPUT_HEADERS))

    if reg_table is not None and reg_table.row_count > 0:
        alerts.rows.extend(_detect_run_keys(reg_table))
    else:
        logger.info("Registry data not available — Run key check skipped.")

    if svc_table is not None and svc_table.row_count > 0:
        alerts.rows.extend(_detect_service_masquerade(svc_table))
    else:
        logger.info("Service data not available — service masquerade check skipped.")

    if task_table is not None and task_table.row_count > 0:
        alerts.rows.extend(_detect_hidden_tasks(task_table))
    else:
        logger.info("Scheduled-task data not available — task check skipped.")

    logger.info("Persistence scan complete: %d total alert(s).", alerts.row_count)
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_alerts_persistence",
        description=(
            "MF-104: Detect persistence mechanisms in registry Run keys, "
            "services, and scheduled tasks."
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
            "Directory containing typed_registry.csv, typed_services.csv, "
            "and/or typed_tasks.csv (default: <case>/csv/)."
        ),
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for alerts_persistence.csv (default: <case>/csv/).",
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

    # -- Locate input CSVs (all optional — at least one should exist) ------- #
    reg_path = in_dir / "typed_registry.csv"
    svc_path = in_dir / "typed_services.csv"
    task_path = in_dir / "typed_tasks.csv"

    reg_table: Optional[RawTable] = None
    svc_table: Optional[RawTable] = None
    task_table: Optional[RawTable] = None

    if reg_path.is_file():
        reg_table = read_csv_safe(reg_path)
        logger.info("Loaded registry data: %d rows.", reg_table.row_count)
    else:
        logger.info("typed_registry.csv not found — Run key rules skipped.")

    if svc_path.is_file():
        svc_table = read_csv_safe(svc_path)
        logger.info("Loaded service data: %d rows.", svc_table.row_count)
    else:
        logger.info("typed_services.csv not found — service rules skipped.")

    if task_path.is_file():
        task_table = read_csv_safe(task_path)
        logger.info("Loaded scheduled-task data: %d rows.", task_table.row_count)
    else:
        logger.info("typed_tasks.csv not found — task rules skipped.")

    if reg_table is None and svc_table is None and task_table is None:
        logger.error(
            "None of typed_registry.csv, typed_services.csv, or "
            "typed_tasks.csv found in %s. Cannot run persistence alerting.",
            in_dir,
        )
        return 2

    # -- Generate alerts ---------------------------------------------------- #
    alerts = generate_persistence_alerts(reg_table, svc_table, task_table)

    # -- Write output ------------------------------------------------------- #
    out_path = out_dir / "alerts_persistence.csv"
    write_csv_safe(alerts, out_path)

    # -- Summary & exit code ------------------------------------------------ #
    logger.info(
        "Persistence alerting complete: %d alert(s) written to %s",
        alerts.row_count,
        out_path,
    )

    return 1 if alerts.row_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

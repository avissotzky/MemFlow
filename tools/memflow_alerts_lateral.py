"""
tools.memflow_alerts_lateral
=============================
**MF-105 — Lateral Movement & Credential Theft Alerting (The Spy Hunter).**

Detects attacker movement through the network by analysing process command
lines and parent-child relationships for credential-dumping tools,
reconnaissance commands, and remote-execution patterns.

Inputs:

- ``typed_process.csv`` — Process list with command lines.
- ``typed_net.csv`` — Network connections (optional, for correlation).

Output: ``<case>/csv/alerts_lateral.csv``.

Detection rules:

1. **CREDENTIAL_DUMP** — Command line matches known credential-dumping
   tools / techniques (mimikatz, sekurlsa, procdump on lsass, comsvcs
   MiniDump).  Severity: **Critical**.
2. **RECON_COMMANDS** — Command line contains reconnaissance commands
   (``net user``, ``whoami``, ``ipconfig /all``, ``systeminfo``,
   ``nltest``).  Severity: **Low** (escalated to **High** if multiple
   distinct recon commands from the same PID / parent).
3. **REMOTE_EXECUTION** — Parent process indicates remote-execution
   framework (``wmiapsrv.exe`` / WMI, or ``services.exe`` / PSEXEC-style)
   spawning ``cmd.exe``.  Severity: **High**.

Usage
-----
::

    python -m tools.memflow_alerts_lateral --case C:\\Cases\\IR-2025-042

    python -m tools.memflow_alerts_lateral \\
        --case ./case1 \\
        --in   ./case1/csv \\
        --out  ./case1/csv
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe
from memflow_rules import load_ruleset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — loaded from memflow_rules/lateral.json
# ---------------------------------------------------------------------------

#: Alert-type tags.
_ALERT_CREDENTIAL_DUMP = "CREDENTIAL_DUMP"
_ALERT_RECON = "RECON_COMMANDS"
_ALERT_REMOTE_EXEC = "REMOTE_EXECUTION"

#: Output CSV headers.
_OUTPUT_HEADERS: List[str] = [
    "alert_type",
    "severity",
    "pid",
    "process_name",
    "ppid",
    "parent_name",
    "cmdline",
    "description",
]

_rules = load_ruleset("lateral")

_CRED_DUMP_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in _rules["cred_dump_patterns"]
]
_RECON_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    (e["label"], re.compile(e["pattern"], re.IGNORECASE))
    for e in _rules["recon_patterns"]
]
_REMOTE_EXEC_PARENTS: Dict[str, str] = _rules["remote_exec_parents"]
_REMOTE_EXEC_CHILDREN: Set[str] = set(_rules["remote_exec_children"])

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


def _resolve_process_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a process table."""
    return {
        "pid":         _find_column(headers, ["pid", "process_id"]),
        "name":        _find_column(headers, ["name", "process_name", "image",
                                              "image_name", "imagename"]),
        "ppid":        _find_column(headers, ["ppid", "parent_pid",
                                              "parent_process_id",
                                              "inheritedfrompid"]),
        "parent_name": _find_column(headers, ["parent_name", "parent_process",
                                              "parent_image", "parent"]),
        "cmdline":     _find_column(headers, ["cmdline", "commandline",
                                              "command_line", "cmd",
                                              "command"]),
    }


def _cell(row: List[str], idx: Optional[int]) -> str:
    """Safely extract a cell value."""
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


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

def generate_lateral_alerts(proc_table: RawTable) -> RawTable:
    """Run all lateral-movement / credential-theft detection rules.

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
    cmdline_idx = cols["cmdline"]

    if pid_idx is None or name_idx is None:
        logger.error(
            "typed_process.csv missing critical columns (pid/name). "
            "Cannot run lateral-movement checks."
        )
        return RawTable(headers=list(_OUTPUT_HEADERS))

    pid_name_map = _build_pid_name_lookup(proc_table, cols)
    alerts = RawTable(headers=list(_OUTPUT_HEADERS))

    # Track recon commands per parent PID for escalation.
    recon_by_parent: Dict[str, Set[str]] = defaultdict(set)
    recon_alert_indices: Dict[str, List[int]] = defaultdict(list)

    for row in proc_table.rows:
        pid_val = _cell(row, pid_idx)
        name_val = _cell(row, name_idx)
        name_lower = name_val.lower()
        ppid_val = _cell(row, cols["ppid"])
        parent_name_raw = _cell(row, cols["parent_name"])
        cmdline = _cell(row, cmdline_idx)
        cmdline_lower = cmdline.lower()

        # Resolve parent name.
        parent_name = parent_name_raw if parent_name_raw else pid_name_map.get(ppid_val, "")
        parent_lower = parent_name.lower()

        # ---- Rule 1: Credential Dumping ----------------------------------
        if cmdline:
            for pattern in _CRED_DUMP_PATTERNS:
                if pattern.search(cmdline):
                    alerts.rows.append([
                        _ALERT_CREDENTIAL_DUMP,
                        "CRITICAL",
                        pid_val,
                        name_val,
                        ppid_val,
                        parent_name,
                        cmdline,
                        (
                            f"Credential-dumping activity detected: "
                            f"'{name_val}' (PID {pid_val}) command line "
                            f"matches '{pattern.pattern}'."
                        ),
                    ])
                    break  # One alert per process.

        # ---- Rule 2: Reconnaissance Commands -----------------------------
        if cmdline:
            for label, pattern in _RECON_PATTERNS:
                if pattern.search(cmdline):
                    idx = len(alerts.rows)
                    alerts.rows.append([
                        _ALERT_RECON,
                        "LOW",      # May be escalated below.
                        pid_val,
                        name_val,
                        ppid_val,
                        parent_name,
                        cmdline,
                        (
                            f"Reconnaissance command '{label}' detected in "
                            f"'{name_val}' (PID {pid_val})."
                        ),
                    ])
                    # Track for parent-based escalation.
                    parent_key = ppid_val if ppid_val else pid_val
                    recon_by_parent[parent_key].add(label)
                    recon_alert_indices[parent_key].append(idx)
                    break  # One alert per process row.

        # ---- Rule 3: Remote Execution ------------------------------------
        if name_lower in _REMOTE_EXEC_CHILDREN and parent_lower in _REMOTE_EXEC_PARENTS:
            framework = _REMOTE_EXEC_PARENTS[parent_lower]
            alerts.rows.append([
                _ALERT_REMOTE_EXEC,
                "HIGH",
                pid_val,
                name_val,
                ppid_val,
                parent_name,
                cmdline,
                (
                    f"Remote execution detected: '{parent_name}' "
                    f"(PPID {ppid_val}, {framework}) spawned "
                    f"'{name_val}' (PID {pid_val}). "
                    f"Indicates lateral movement."
                ),
            ])

    # -- Escalate grouped recon commands ----------------------------------- #
    for parent_key, labels in recon_by_parent.items():
        if len(labels) >= 3:
            # Escalate all recon alerts from this parent to HIGH.
            for idx in recon_alert_indices[parent_key]:
                if idx < len(alerts.rows):
                    alerts.rows[idx][1] = "HIGH"  # severity column
                    alerts.rows[idx][7] += (  # description column
                        f" [ESCALATED: {len(labels)} distinct recon commands "
                        f"from same parent — likely automated enumeration.]"
                    )

    logger.info(
        "Lateral-movement scan complete: %d alert(s) from %d process(es).",
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
        prog="memflow_alerts_lateral",
        description=(
            "MF-105: Detect lateral movement, credential theft, and "
            "reconnaissance from process command lines."
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
        help="Output directory for alerts_lateral.csv (default: <case>/csv/).",
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
            out_dir / "alerts_lateral.csv",
        )
        return 0

    # -- Generate alerts ---------------------------------------------------- #
    alerts = generate_lateral_alerts(proc_table)

    # -- Write output ------------------------------------------------------- #
    out_path = out_dir / "alerts_lateral.csv"
    write_csv_safe(alerts, out_path)

    # -- Summary & exit code ------------------------------------------------ #
    logger.info(
        "Lateral-movement alerting complete: %d alert(s) written to %s",
        alerts.row_count,
        out_path,
    )

    return 1 if alerts.row_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

"""
tools.memflow_alerts_network
=============================
**MF-101 — Network Anomaly Alerting (The Beacon Hunter).**

Joins ``typed_net.csv`` with ``typed_process.csv`` (and optionally
``typed_dns.csv``) on PID to identify four classes of suspicious network
activity:

1. **PROCESS_PORT_MISMATCH** — A non-browser process owns a connection on
   port 80 or 443 (potential C2 beacon, web-shell, or LOLBin abuse).
2. **LISTENER_TRAP** — A process is LISTENING on a port and is not in the
   approved-servers list (potential backdoor).
3. **HIGH_PORT_EXTERNAL** — A process connects to a non-private remote IP
   on a destination port > 1024 (potential C2 on ephemeral ports).
4. **RARE_DNS_QUERY** — ``powershell.exe`` or ``cmd.exe`` resolved a domain
   name (scripts downloading payloads).

Outputs
-------
- ``<case>/csv/alerts_network.csv`` — One row per flagged connection.

Usage
-----
::

    python -m tools.memflow_alerts_network --case C:\\Cases\\IR-2025-042

    python -m tools.memflow_alerts_network \
        --case ./case1 \
        --in   ./case1/csv \
        --out  ./case1/csv
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe
from memflow_rules import load_ruleset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — loaded from memflow_rules/network.json
# ---------------------------------------------------------------------------

_rules = load_ruleset("network")

_BROWSERS: Set[str] = set(_rules["browsers"])
_APPROVED_LISTENERS: Set[str] = set(_rules["approved_listeners"])
_SUSPICIOUS_DNS_RESOLVERS: Set[str] = set(_rules["suspicious_dns_resolvers"])
_WEB_PORTS: Set[int] = set(_rules["web_ports"])
_WELL_KNOWN_PORT_CEILING: int = _rules["well_known_port_ceiling"]

del _rules

#: Alert-type tag strings.
_ALERT_PROCESS_PORT_MISMATCH = "PROCESS_PORT_MISMATCH"
_ALERT_LISTENER_TRAP = "LISTENER_TRAP"
_ALERT_HIGH_PORT_EXTERNAL = "HIGH_PORT_EXTERNAL"
_ALERT_RARE_DNS = "RARE_DNS_QUERY"

#: Output CSV headers.
_OUTPUT_HEADERS: List[str] = [
    "alert_type",
    "severity",
    "pid",
    "process_name",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
    "protocol",
    "state",
    "description",
]


# ---------------------------------------------------------------------------
# Column-name resolution helpers
# ---------------------------------------------------------------------------

def _find_column(headers: List[str], candidates: List[str]) -> Optional[int]:
    """Return the index of the first matching header (case-insensitive).

    Parameters
    ----------
    headers : list[str]
        Header row from the CSV.
    candidates : list[str]
        Column-name candidates in priority order.

    Returns
    -------
    int or None
        Column index, or ``None`` if no candidate matched.
    """
    lower_headers = [h.lower().strip() for h in headers]
    for candidate in candidates:
        if candidate.lower() in lower_headers:
            return lower_headers.index(candidate.lower())
    return None


def _resolve_net_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a net / netscan table."""
    return {
        "pid":      _find_column(headers, ["pid", "process_id"]),
        "src_addr": _find_column(headers, ["src-addr", "src_addr", "local-addr",
                                           "local_addr", "localaddr", "srcaddr"]),
        "src_port": _find_column(headers, ["src-port", "src_port", "local-port",
                                           "local_port", "localport", "srcport"]),
        "dst_addr": _find_column(headers, ["dst-addr", "dst_addr", "remote-addr",
                                           "remote_addr", "remoteaddr", "dstaddr",
                                           "foreign-addr", "foreign_addr"]),
        "dst_port": _find_column(headers, ["dst-port", "dst_port", "remote-port",
                                           "remote_port", "remoteport", "dstport",
                                           "foreign-port", "foreign_port"]),
        "protocol": _find_column(headers, ["protocol", "proto", "type"]),
        "state":    _find_column(headers, ["state", "st", "status"]),
    }


def _resolve_process_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a process table."""
    return {
        "pid":  _find_column(headers, ["pid", "process_id"]),
        "name": _find_column(headers, ["name", "process_name", "image",
                                       "image_name", "imagename"]),
    }


def _resolve_dns_columns(headers: List[str]) -> Dict[str, Optional[int]]:
    """Map logical column names to indices for a DNS table."""
    return {
        "pid":    _find_column(headers, ["pid", "process_id"]),
        "name":   _find_column(headers, ["name", "process_name", "process",
                                         "image", "image_name"]),
        "query":  _find_column(headers, ["query", "domain", "dns_query",
                                         "hostname", "host", "record",
                                         "query_name"]),
    }


# ---------------------------------------------------------------------------
# PID → Process name lookup
# ---------------------------------------------------------------------------

def build_pid_lookup(proc_table: RawTable) -> Dict[str, str]:
    """Build a ``{pid: process_name}`` dict from the typed process table.

    Returns
    -------
    dict
        Mapping from PID strings to lower-cased process names.
    """
    cols = _resolve_process_columns(proc_table.headers)
    pid_idx = cols["pid"]
    name_idx = cols["name"]

    if pid_idx is None:
        logger.error("typed_process.csv has no recognisable 'pid' column.")
        return {}
    if name_idx is None:
        logger.warning(
            "typed_process.csv has no recognisable 'name' column — "
            "all processes will be treated as unknown."
        )
        return {}

    lookup: Dict[str, str] = {}
    for row in proc_table.rows:
        pid_val = row[pid_idx].strip() if pid_idx < len(row) else ""
        name_val = row[name_idx].strip() if name_idx < len(row) else ""
        if pid_val:
            lookup[pid_val] = name_val

    logger.info("Process lookup built: %d unique PIDs.", len(lookup))
    return lookup


# ---------------------------------------------------------------------------
# Core alert logic
# ---------------------------------------------------------------------------

def _safe_int(value: str) -> Optional[int]:
    """Parse a string as an integer, returning ``None`` on failure."""
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        # Try hex (MemProcFS sometimes emits hex port values after typing)
        try:
            return int(value, 16)
        except ValueError:
            return None


def _cell(row: List[str], idx: Optional[int]) -> str:
    """Safely extract a cell value."""
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


def _is_private_ip(addr: str) -> bool:
    """Return ``True`` if *addr* is a private / reserved IP address.

    Covers RFC 1918 (10.x, 172.16-31.x, 192.168.x), loopback (127.x),
    link-local, and other reserved ranges via the stdlib.
    """
    addr = addr.strip()
    if not addr or addr in ("*", "0.0.0.0", "::", "0"):
        return True
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        # Unparseable address — treat as non-private to surface for review.
        return False


def generate_network_alerts(
    net_table: RawTable,
    pid_lookup: Dict[str, str],
) -> RawTable:
    """Scan every row in the network table and emit alert rows.

    Rules implemented:
    - PROCESS_PORT_MISMATCH: Non-browser on port 80/443 (Medium).
    - LISTENER_TRAP: LISTENING state, not in approved servers (High).
    - HIGH_PORT_EXTERNAL: Remote port > 1024, remote IP not private (Medium).

    Parameters
    ----------
    net_table : RawTable
        The ``typed_net.csv`` table.
    pid_lookup : dict
        ``{pid: process_name}`` from the process table.

    Returns
    -------
    RawTable
        Alert table ready for ``write_csv_safe``.
    """
    cols = _resolve_net_columns(net_table.headers)

    pid_idx = cols["pid"]
    if pid_idx is None:
        logger.error("typed_net.csv has no recognisable 'pid' column — cannot correlate.")
        return RawTable(headers=_OUTPUT_HEADERS)

    alerts = RawTable(headers=list(_OUTPUT_HEADERS))

    for row in net_table.rows:
        pid_val = _cell(row, pid_idx)
        proc_name = pid_lookup.get(pid_val, "<unknown>")
        proc_lower = proc_name.lower()

        src_addr = _cell(row, cols["src_addr"])
        src_port_raw = _cell(row, cols["src_port"])
        dst_addr = _cell(row, cols["dst_addr"])
        dst_port_raw = _cell(row, cols["dst_port"])
        protocol = _cell(row, cols["protocol"])
        state = _cell(row, cols["state"])

        src_port = _safe_int(src_port_raw)
        dst_port = _safe_int(dst_port_raw)
        state_upper = state.upper()

        # ---- Rule 1: Process-Port Mismatch (Non-browser on web ports) -----
        remote_port = dst_port
        if remote_port is not None and remote_port in _WEB_PORTS:
            if proc_lower not in _BROWSERS:
                alerts.rows.append([
                    _ALERT_PROCESS_PORT_MISMATCH,
                    "MEDIUM",
                    pid_val,
                    proc_name,
                    src_addr,
                    src_port_raw,
                    dst_addr,
                    dst_port_raw,
                    protocol,
                    state,
                    (
                        f"Non-browser process '{proc_name}' (PID {pid_val}) "
                        f"communicating on web port {remote_port}. "
                        f"Malware often uses standard web ports to blend in."
                    ),
                ])

        # ---- Rule 2: Listener Trap (LISTENING + not approved) -------------
        if "LISTEN" in state_upper:
            if proc_lower not in _APPROVED_LISTENERS:
                listen_port = src_port_raw or dst_port_raw
                alerts.rows.append([
                    _ALERT_LISTENER_TRAP,
                    "HIGH",
                    pid_val,
                    proc_name,
                    src_addr,
                    src_port_raw,
                    dst_addr,
                    dst_port_raw,
                    protocol,
                    state,
                    (
                        f"Process '{proc_name}' (PID {pid_val}) is LISTENING "
                        f"on port {listen_port}. Not in approved server list. "
                        f"Possible backdoor."
                    ),
                ])

        # ---- Rule 3: High-Port External Communication --------------------
        if dst_port is not None and dst_port > _WELL_KNOWN_PORT_CEILING:
            if not _is_private_ip(dst_addr):
                alerts.rows.append([
                    _ALERT_HIGH_PORT_EXTERNAL,
                    "MEDIUM",
                    pid_val,
                    proc_name,
                    src_addr,
                    src_port_raw,
                    dst_addr,
                    dst_port_raw,
                    protocol,
                    state,
                    (
                        f"Process '{proc_name}' (PID {pid_val}) connected to "
                        f"external IP {dst_addr} on high port {dst_port}. "
                        f"C2 servers often use ephemeral ports."
                    ),
                ])

    logger.info(
        "Network alert scan complete: %d alert(s) from %d connection(s).",
        alerts.row_count,
        net_table.row_count,
    )
    return alerts


def generate_dns_alerts(
    dns_table: RawTable,
    pid_lookup: Dict[str, str],
) -> RawTable:
    """Scan DNS query table for suspicious resolver processes.

    Rule: RARE_DNS_QUERY — powershell.exe or cmd.exe resolving domains (High).

    Parameters
    ----------
    dns_table : RawTable
        The ``typed_dns.csv`` table.
    pid_lookup : dict
        ``{pid: process_name}`` from the process table.

    Returns
    -------
    RawTable
        Alert rows (same header schema as network alerts).
    """
    cols = _resolve_dns_columns(dns_table.headers)

    pid_idx = cols["pid"]
    name_idx = cols["name"]
    query_idx = cols["query"]

    alerts = RawTable(headers=list(_OUTPUT_HEADERS))

    for row in dns_table.rows:
        pid_val = _cell(row, pid_idx)
        # Prefer the name column in DNS table; fall back to PID lookup.
        proc_name = _cell(row, name_idx)
        if not proc_name and pid_val:
            proc_name = pid_lookup.get(pid_val, "<unknown>")
        proc_lower = proc_name.lower()

        query = _cell(row, query_idx)

        if proc_lower in _SUSPICIOUS_DNS_RESOLVERS and query:
            alerts.rows.append([
                _ALERT_RARE_DNS,
                "HIGH",
                pid_val,
                proc_name,
                "",       # src_addr
                "",       # src_port
                query,    # dst_addr — domain queried
                "",       # dst_port
                "DNS",    # protocol
                "",       # state
                (
                    f"Script host '{proc_name}' (PID {pid_val}) resolved "
                    f"domain '{query}'. Scripts rarely resolve DNS directly "
                    f"unless downloading payloads."
                ),
            ])

    logger.info(
        "DNS alert scan complete: %d alert(s) from %d query(ies).",
        alerts.row_count,
        dns_table.row_count,
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_alerts_network",
        description=(
            "MF-101: Detect suspicious network activity by joining "
            "typed_net.csv with typed_process.csv (and optionally typed_dns.csv)."
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
        help="Directory containing typed CSVs (default: <case>/csv/).",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for alerts_network.csv (default: <case>/csv/).",
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

    # -- Locate required CSVs ----------------------------------------------- #
    net_path = in_dir / "typed_net.csv"
    proc_path = in_dir / "typed_process.csv"
    dns_path = in_dir / "typed_dns.csv"

    if not net_path.is_file():
        logger.error("Required file not found: %s", net_path)
        return 2

    if not proc_path.is_file():
        logger.error("Required file not found: %s", proc_path)
        return 2

    # -- Load tables -------------------------------------------------------- #
    net_table = read_csv_safe(net_path)
    proc_table = read_csv_safe(proc_path)

    # -- Build PID lookup --------------------------------------------------- #
    pid_lookup = build_pid_lookup(proc_table)

    # -- Generate network alerts -------------------------------------------- #
    all_alert_rows: List[List[str]] = []

    if net_table.row_count == 0:
        logger.warning("typed_net.csv has no data rows — skipping network rules.")
    else:
        net_alerts = generate_network_alerts(net_table, pid_lookup)
        all_alert_rows.extend(net_alerts.rows)

    # -- Generate DNS alerts (optional input) ------------------------------- #
    if dns_path.is_file():
        dns_table = read_csv_safe(dns_path)
        if dns_table.row_count > 0:
            dns_alerts = generate_dns_alerts(dns_table, pid_lookup)
            all_alert_rows.extend(dns_alerts.rows)
        else:
            logger.warning("typed_dns.csv has no data rows — skipping DNS rules.")
    else:
        logger.info("typed_dns.csv not found — DNS alerting skipped.")

    # -- Assemble & write output -------------------------------------------- #
    combined = RawTable(headers=list(_OUTPUT_HEADERS))
    combined.rows = all_alert_rows

    out_path = out_dir / "alerts_network.csv"
    write_csv_safe(combined, out_path)

    # -- Summary & exit code ------------------------------------------------ #
    logger.info(
        "Network alerting complete: %d alert(s) written to %s",
        combined.row_count,
        out_path,
    )

    return 1 if combined.row_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

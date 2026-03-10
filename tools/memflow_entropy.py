"""
tools.memflow_entropy
=====================
**MF-080 — Entropy Enrichment.**

Reads a ``files.csv`` (or ``typed_files.csv``) table listing forensic file
paths, locates the actual file content on disk, and computes:

- **Shannon Entropy** (0.0 – 8.0) — high entropy suggests encryption,
  compression, or packed executables.
- **MD5** hash.
- **SHA-256** hash.

The output CSV is joinable back to the source table on the file-path column.

Outputs
-------
- ``<case>/csv/file_entropy.csv``

Usage
-----
::

    python -m tools.memflow_entropy \\
        --case C:\\Cases\\IR-2025-042 \\
        --in   C:\\Cases\\IR-2025-042\\csv\\files.csv

    python -m tools.memflow_entropy \\
        --case ./case1 \\
        --in   ./case1/csv/typed_files.csv \\
        --forensic-dir ./case1/forensic_files
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Entropy & hash calculations
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Parameters
    ----------
    data : bytes
        Raw file content.

    Returns
    -------
    float
        Entropy value between 0.0 (perfectly uniform / empty) and 8.0
        (maximum entropy — every byte value equally likely).
    """
    if not data:
        return 0.0

    length = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 6)


def compute_hashes(data: bytes) -> Tuple[str, str]:
    """Return ``(md5_hex, sha256_hex)`` for the given bytes."""
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


# ---------------------------------------------------------------------------
# File-path resolution
# ---------------------------------------------------------------------------

# Common column names that might contain the file path in a MemProcFS CSV.
_PATH_COLUMN_CANDIDATES = (
    "file",
    "filepath",
    "file_path",
    "path",
    "name",
    "filename",
    "file_name",
    "File",
    "FilePath",
    "Path",
    "Name",
)

# Common column names for a unique file identifier.
_ID_COLUMN_CANDIDATES = (
    "file_id",
    "fileid",
    "id",
    "File_ID",
    "FileID",
    "ID",
)


def _find_column(headers: List[str], candidates: tuple) -> Optional[int]:
    """Return the index of the first header that matches any candidate name."""
    header_lower = {h.lower().strip(): i for i, h in enumerate(headers)}
    for candidate in candidates:
        idx = header_lower.get(candidate.lower())
        if idx is not None:
            return idx
    return None


def _resolve_file(
    raw_path: str,
    forensic_dir: Path,
) -> Optional[Path]:
    """Try to resolve a file path from the CSV against the forensic directory.

    The CSV may contain absolute VFS paths (e.g. from MemProcFS) that don't
    exist on the current system.  We try several strategies:

    1. Exact match as an absolute path.
    2. Relative to *forensic_dir*.
    3. Basename match inside *forensic_dir* (flat layout).
    """
    if not raw_path or not raw_path.strip():
        return None

    raw_path = raw_path.strip()

    # 1. Absolute path?
    candidate = Path(raw_path)
    if candidate.is_file():
        return candidate

    # 2. Relative to forensic_dir
    candidate = forensic_dir / raw_path
    if candidate.is_file():
        return candidate

    # 3. Strip leading slashes / drive letters and try relative
    # Handle paths like  "C:\Windows\System32\foo.dll"  or  "/proc/123/maps"
    stripped = raw_path.lstrip("/").lstrip("\\")
    # Remove drive letter prefix (e.g. "C:\")
    if len(stripped) >= 2 and stripped[1] == ":":
        stripped = stripped[2:].lstrip("/").lstrip("\\")
    candidate = forensic_dir / stripped
    if candidate.is_file():
        return candidate

    # 4. Basename only
    basename = Path(raw_path).name
    candidate = forensic_dir / basename
    if candidate.is_file():
        return candidate

    return None


# ---------------------------------------------------------------------------
# Core enrichment logic
# ---------------------------------------------------------------------------

def enrich_files(
    files_csv_path: Path,
    forensic_dir: Path,
) -> RawTable:
    """Read a files CSV and produce an entropy-enriched output table.

    Parameters
    ----------
    files_csv_path : Path
        Path to the ``files.csv`` or ``typed_files.csv`` input.
    forensic_dir : Path
        Base directory where actual forensic file content is stored.

    Returns
    -------
    RawTable
        A new table with columns:
        ``file_path``, ``file_id``, ``entropy``, ``md5``, ``sha256``,
        ``file_size``, ``status``.
    """
    source = read_csv_safe(files_csv_path)

    # Detect the path column
    path_col_idx = _find_column(source.headers, _PATH_COLUMN_CANDIDATES)
    if path_col_idx is None:
        logger.error(
            "Cannot find a file-path column in %s. Headers: %s",
            files_csv_path.name, source.headers,
        )
        # Fall back to first column
        path_col_idx = 0
        logger.warning("Falling back to first column '%s' as file path.", source.headers[0])

    # Detect optional ID column
    id_col_idx = _find_column(source.headers, _ID_COLUMN_CANDIDATES)

    path_col_name = source.headers[path_col_idx]
    logger.info(
        "Using column '%s' (index %d) as file path source.",
        path_col_name, path_col_idx,
    )

    # Build output table
    output = RawTable(
        headers=["file_path", "file_id", "entropy", "md5", "sha256", "file_size", "status"],
    )

    found = 0
    not_found = 0

    for row_idx, row in enumerate(source.rows):
        raw_path = row[path_col_idx] if path_col_idx < len(row) else ""

        # Grab ID if present
        file_id = ""
        if id_col_idx is not None and id_col_idx < len(row):
            file_id = row[id_col_idx]

        resolved = _resolve_file(raw_path, forensic_dir)

        if resolved is None:
            output.rows.append([
                raw_path, file_id, "", "", "", "", "not_found",
            ])
            not_found += 1
            logger.debug("Row %d: file not found — '%s'", row_idx, raw_path)
            continue

        try:
            data = resolved.read_bytes()
        except (PermissionError, OSError) as exc:
            output.rows.append([
                raw_path, file_id, "", "", "", "", f"read_error: {exc}",
            ])
            not_found += 1
            logger.warning("Row %d: cannot read '%s': %s", row_idx, resolved, exc)
            continue

        entropy = shannon_entropy(data)
        md5, sha256 = compute_hashes(data)
        file_size = str(len(data))

        output.rows.append([
            raw_path, file_id,
            f"{entropy:.6f}", md5, sha256, file_size, "ok",
        ])
        found += 1
        logger.debug(
            "Row %d: '%s' — entropy=%.4f, size=%s",
            row_idx, raw_path, entropy, file_size,
        )

    logger.info(
        "Entropy enrichment: %d file(s) processed, %d found, %d not found.",
        len(source.rows), found, not_found,
    )
    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_entropy",
        description=(
            "MF-080: Compute Shannon entropy and cryptographic hashes for "
            "forensic files listed in a CSV."
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
        help="Path to files.csv (or typed_files.csv) listing forensic files.",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for file_entropy.csv (default: <case>/csv/).",
    )
    parser.add_argument(
        "--forensic-dir", "-f",
        dest="forensic_dir",
        type=Path,
        default=None,
        help=(
            "Directory containing actual forensic file content "
            "(default: <case>/forensic_files/)."
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
    """Entry point.  Returns 0 on success, 1 on partial (some files missing), 2 on fatal."""
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
    forensic_dir: Path = (
        args.forensic_dir or (case_dir / "forensic_files")
    ).resolve()

    # -- Startup validation ------------------------------------------------- #
    if not case_dir.exists():
        logger.warning("Case directory does not exist, creating: %s", case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)

    if not in_path.is_file():
        logger.error("Input file does not exist: %s", in_path)
        return 2

    if not forensic_dir.is_dir():
        logger.warning(
            "Forensic directory does not exist: %s — "
            "all files will be marked 'not_found'.",
            forensic_dir,
        )

    out_dir.mkdir(parents=True, exist_ok=True)

    # -- Enrich ------------------------------------------------------------- #
    output = enrich_files(in_path, forensic_dir)

    # -- Write output ------------------------------------------------------- #
    out_path = out_dir / "file_entropy.csv"
    write_csv_safe(output, out_path)
    logger.info("Entropy CSV written: %s (%d rows)", out_path, output.row_count)

    # -- Exit code ---------------------------------------------------------- #
    not_found = sum(1 for row in output.rows if row[-1] != "ok")
    if not_found > 0:
        logger.warning(
            "%d of %d file(s) could not be read — see 'status' column.",
            not_found, output.row_count,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

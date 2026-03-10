"""Base class and shared helpers for all MemProcFS data extractors.

Every extractor inherits from :class:`BaseExtractor`, declares a few class
attributes, and implements :meth:`extract`.  The orchestrator
(:file:`run_extract.py`) auto-discovers all concrete subclasses and calls
them in turn with a shared VMM session.
"""

from __future__ import annotations

import csv
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

READ_CHUNK_SIZE = 0x0010_0000  # 1 MiB per VFS read call
VFS_CSV_PATH = "/forensic/csv/"


@dataclass
class ExtractResult:
    """Outcome returned by every extractor run."""

    ok: bool = True
    rows: int = 0
    files_written: List[str] = field(default_factory=list)
    error: Optional[str] = None


class BaseExtractor(ABC):
    """Abstract base for a single extraction capability.

    Subclasses **must** set the three class-level attributes and implement
    :meth:`extract`.  Everything else is inherited.
    """

    # -- Subclass must override ------------------------------------------------
    name: str = ""
    """Short, unique identifier used for ``--only`` / ``--exclude`` filtering."""

    output_filename: str = ""
    """Default CSV filename written into ``out_dir``."""

    source: str = ""
    """One of ``"api"``, ``"vfs"``, or ``"forensic_csv"``."""

    # -- Shared helpers --------------------------------------------------------

    @abstractmethod
    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        """Pull data from *vmm*, write CSV(s) to *out_dir*, return result."""
        ...

    # -- CSV writing -----------------------------------------------------------

    @staticmethod
    def write_csv(
        out_dir: Path,
        filename: str,
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
    ) -> Path:
        """Write *rows* as a strictly-quoted UTF-8 CSV and return the path."""
        filepath = out_dir / filename
        with filepath.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(row)
        logger.info("  [+] Wrote %s (%d rows)", filepath.name, len(rows))
        return filepath

    # -- VFS helpers -----------------------------------------------------------

    @staticmethod
    def read_vfs_file(vmm: Any, vfs_path: str, file_size: int) -> bytes:
        """Chunked read of a VFS file.  Returns the full content as bytes."""
        chunks: list[bytes] = []
        offset = 0
        while offset < file_size:
            chunk_len = min(READ_CHUNK_SIZE, file_size - offset)
            buf = vmm.vfs.read(vfs_path, chunk_len, offset)
            if not buf:
                break
            chunks.append(buf)
            offset += len(buf)
        return b"".join(chunks)

    @staticmethod
    def read_vfs_text(
        vmm: Any,
        vfs_path: str,
        max_size: int = 10_000_000,
    ) -> str:
        """Read a VFS text file and decode it as UTF-8 (lossy)."""
        raw = vmm.vfs.read(vfs_path, max_size, 0)
        return raw.decode(errors="replace") if raw else ""

    @staticmethod
    def copy_forensic_csv(
        vmm: Any,
        csv_name: str,
        out_dir: Path,
    ) -> ExtractResult:
        """Copy a single CSV from ``/forensic/csv/`` to *out_dir*.

        Returns an :class:`ExtractResult` with a row count derived from
        the line count of the file (header excluded).
        """
        listing: Dict[str, Dict[str, Any]] = vmm.vfs.list(VFS_CSV_PATH)
        if csv_name not in listing:
            msg = f"{csv_name} not found in {VFS_CSV_PATH}"
            logger.warning("  [!] %s", msg)
            return ExtractResult(ok=False, error=msg)

        file_size: int = listing[csv_name].get("size", 0)
        vfs_path = f"{VFS_CSV_PATH}{csv_name}"
        local_path = out_dir / csv_name

        offset = 0
        with local_path.open("wb") as fh:
            while offset < file_size:
                chunk_len = min(READ_CHUNK_SIZE, file_size - offset)
                buf = vmm.vfs.read(vfs_path, chunk_len, offset)
                if not buf:
                    break
                fh.write(buf)
                offset += len(buf)

        row_count = max(0, local_path.read_text(encoding="utf-8", errors="replace").count("\n") - 1)
        logger.info("  [+] Copied %s (%d bytes, ~%d rows)", csv_name, offset, row_count)
        return ExtractResult(ok=True, rows=row_count, files_written=[csv_name])

    @staticmethod
    def copy_forensic_csvs_matching(
        vmm: Any,
        prefix: str,
        out_dir: Path,
    ) -> ExtractResult:
        """Copy all forensic CSVs whose name starts with *prefix*.

        Useful for ``timeline_*.csv`` which is a family of related files.
        """
        listing: Dict[str, Dict[str, Any]] = vmm.vfs.list(VFS_CSV_PATH)
        matches = sorted(n for n in listing if n.startswith(prefix))
        if not matches:
            msg = f"No forensic CSVs matching prefix '{prefix}'"
            logger.warning("  [!] %s", msg)
            return ExtractResult(ok=False, error=msg)

        total_rows = 0
        files: list[str] = []
        for csv_name in matches:
            file_size: int = listing[csv_name].get("size", 0)
            vfs_path = f"{VFS_CSV_PATH}{csv_name}"
            local_path = out_dir / csv_name

            offset = 0
            with local_path.open("wb") as fh:
                while offset < file_size:
                    chunk_len = min(READ_CHUNK_SIZE, file_size - offset)
                    buf = vmm.vfs.read(vfs_path, chunk_len, offset)
                    if not buf:
                        break
                    fh.write(buf)
                    offset += len(buf)

            rows = max(
                0,
                local_path.read_text(encoding="utf-8", errors="replace").count("\n") - 1,
            )
            total_rows += rows
            files.append(csv_name)
            logger.info("  [+] Copied %s (%d bytes, ~%d rows)", csv_name, offset, rows)

        return ExtractResult(ok=True, rows=total_rows, files_written=files)

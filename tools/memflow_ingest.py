"""
tools.memflow_ingest
====================
**MF-010 / MF-015 — The Raw Data Miner & Total Dump Extractor.**

Connects to the MemProcFS library, initialises the forensic engine against a
raw memory dump, and extracts **every** generated CSV from the virtual file
system to the local investigation directory.

This is the very first entry point of the MemFlow pipeline.  Output CSVs
land in ``<case>/csv/`` and become the input for every downstream tool
(inventory, parsing, alerting, etc.).

When the ``--full-dump`` flag is provided (MF-015), the script additionally
performs a deep artifact extraction — copying registry hives, suspicious
process minidumps (based on FindEvil results), recovered executables, and
the raw FindEvil report.

.. warning::
   ``--full-dump`` can produce output roughly 2x the size of the original
   RAM image.  Make sure you have sufficient disk space.

Outputs
-------
- ``<out>/*.csv`` — Every CSV produced by the MemProcFS forensic scanner
  (``process.csv``, ``net.csv``, ``files.csv``, ``timeline.csv``, etc.).

When ``--full-dump`` is active, the following additional artifacts are
created under ``<case>/``:

- ``raw/registry/``         — SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT hives.
- ``raw/dumps/``            — Minidumps of malicious PIDs flagged by FindEvil.
- ``raw/files/``            — Open-handle files for flagged PIDs.
- ``raw/recovered_files/``  — Recovered ``.exe``, ``.dll``, ``.ps1``, ``.bat``,
  ``.sys`` files from the forensic file-carving pass.
- ``docs/findevil_raw.txt`` — The verbatim FindEvil report.

Usage
-----
::

    python -m tools.memflow_ingest \\
        --case  C:\\Cases\\IR-2025-042 \\
        --device C:\\Dumps\\mem.raw

    python -m tools.memflow_ingest \\
        --case  C:\\Cases\\IR-2025-042 \\
        --device mem.raw \\
        --out   C:\\Cases\\IR-2025-042\\csv \\
        --wait  30 \\
        --log-level DEBUG

    # Full scene-clone with deep extraction:
    python -m tools.memflow_ingest \\
        --case  C:\\Cases\\IR-2025-042 \\
        --device C:\\Dumps\\mem.raw \\
        --full-dump

"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import memprocfs
except ImportError:
    memprocfs = None  # Handled at runtime with a clear error message.

logger = logging.getLogger(__name__)

# Default mount letter for MemProcFS subprocess fallback
MEMPROCFS_MOUNT_LETTER = "M"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VFS_CSV_PATH = "/forensic/csv/"
READ_CHUNK_SIZE = 0x0010_0000  # 1 MiB per VFS read call
DEFAULT_INIT_WAIT_SECONDS = 15
POLL_INTERVAL_SECONDS = 2

# -- MF-015  Deep-extraction paths & filters -------------------------------- #
VFS_REGISTRY_PATH = "/registry/hive_files/"
VFS_PID_ROOT = "/pid/"
VFS_FORENSIC_FILES = "/forensic/files/"
VFS_FINDEVIL_REPORT = "/forensic/findevil/findevil.txt"

REGISTRY_HIVES = ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")
RECOVERED_EXTENSIONS = frozenset((".exe", ".dll", ".ps1", ".bat", ".sys"))


# ---------------------------------------------------------------------------
# MemProcFS subprocess fallback (when Python API fails)
# ---------------------------------------------------------------------------

def _find_memprocfs_exe(override: Optional[Path] = None) -> Optional[Path]:
    """Locate MemProcFS.exe in project dir or PATH."""
    if override is not None and override.is_file():
        return override
    project_root = Path(__file__).resolve().parents[1]
    candidates = [
        project_root / "MemProcFS_extract" / "MemProcFS.exe",
        project_root / "MemProcFS" / "MemProcFS.exe",
    ]
    for p in candidates:
        if p.is_file():
            return p
    exe_in_path = shutil.which("MemProcFS.exe")
    if exe_in_path:
        return Path(exe_in_path)
    return None


def _extract_via_memprocfs_exe(
    device_path: Path,
    out_dir: Path,
    wait_seconds: int,
    mount_letter: str = MEMPROCFS_MOUNT_LETTER,
    memprocfs_exe: Optional[Path] = None,
) -> Tuple[int, int]:
    """Run MemProcFS.exe as subprocess, copy CSVs from mount, return (ok, errors)."""
    exe_path = _find_memprocfs_exe(memprocfs_exe)
    if not exe_path:
        logger.error(
            "MemProcFS.exe not found. Download from "
            "https://github.com/ufrisk/MemProcFS/releases and extract to "
            "MemProcFS_extract/ or add to PATH."
        )
        return 0, 1

    mount_root = Path(f"{mount_letter}:\\")
    csv_mount = mount_root / "forensic" / "csv"

    logger.info(
        "Using MemProcFS.exe fallback: %s (Python API failed)",
        exe_path,
    )
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    proc = subprocess.Popen(
        [
            str(exe_path),
            "-device", str(device_path),
            "-forensic", "1",
            "-forensic-scan-ranges", "1",
            "-csv",
            "-disable-python",
            "-mount", mount_letter,
        ],
        cwd=str(exe_path.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )

    try:
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if csv_mount.is_dir():
                files = list(csv_mount.iterdir())
                if files:
                    break
            time.sleep(POLL_INTERVAL_SECONDS)

        if not csv_mount.is_dir():
            logger.error(
                "MemProcFS mount %s did not appear within %d s. "
                "Manual workaround: run 'MemProcFS.exe -device \"%s\" -forensic 1 "
                "-disable-python -mount M' in a separate terminal, wait for the forensic scan, "
                "copy %s\\* to %s, then run memflow-inventory.",
                csv_mount, wait_seconds, device_path, csv_mount, out_dir,
            )
            return 0, 1

        ok, errors = 0, 0
        for f in csv_mount.iterdir():
            if f.is_file():
                try:
                    dest = out_dir / f.name
                    shutil.copy2(f, dest)
                    logger.info("  [+] Extracted %s (%d bytes)", f.name, dest.stat().st_size)
                    ok += 1
                except Exception as exc:  # noqa: BLE001
                    logger.error("  [!] Failed to extract %s: %s", f.name, exc)
                    errors += 1
        return ok, errors
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# VFS helpers
# ---------------------------------------------------------------------------

def wait_for_csv_directory(
    vmm: Any,
    wait_seconds: int = DEFAULT_INIT_WAIT_SECONDS,
) -> bool:
    """Block until the VFS CSV directory is populated or *wait_seconds* elapses.

    Polls every :data:`POLL_INTERVAL_SECONDS` seconds so that we proceed as
    soon as the directory appears rather than always sleeping the maximum.
    """
    logger.info("Waiting up to %d s for forensic CSV generation …", wait_seconds)
    deadline = time.monotonic() + wait_seconds

    while time.monotonic() < deadline:
        try:
            listing = vmm.vfs.list(VFS_CSV_PATH)
            if listing:
                logger.debug("VFS CSV directory is ready (%d entries).", len(listing))
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(POLL_INTERVAL_SECONDS)

    # One final attempt after the deadline.
    try:
        return bool(vmm.vfs.list(VFS_CSV_PATH))
    except Exception:  # noqa: BLE001
        return False


def extract_file(
    vmm: Any,
    vfs_path: str,
    local_path: Path,
    file_size: int,
) -> int:
    """Read a single file from the VFS and write it to *local_path*.

    Large files are read in 1 MiB chunks to avoid excessive memory pressure
    on multi-gigabyte forensic dumps.

    Returns the number of bytes written.
    """
    bytes_written = 0
    with local_path.open("wb") as fh:
        offset = 0
        while offset < file_size:
            chunk_len = min(READ_CHUNK_SIZE, file_size - offset)
            data = vmm.vfs.read(vfs_path, chunk_len, offset)
            if not data:
                break
            fh.write(data)
            bytes_written += len(data)
            offset += len(data)
    return bytes_written


def extract_all_csvs(vmm: Any, out_dir: Path) -> Tuple[int, int]:
    """Copy every file from :data:`VFS_CSV_PATH` into *out_dir*.

    Returns ``(success_count, error_count)``.
    """
    listing: Dict[str, Dict[str, Any]] = vmm.vfs.list(VFS_CSV_PATH)
    total = len(listing)
    logger.info("Found %d file(s) in %s — starting extraction.", total, VFS_CSV_PATH)

    ok = 0
    errors = 0

    for filename in sorted(listing):
        info = listing[filename]
        vfs_path = f"{VFS_CSV_PATH}{filename}"
        local_path = out_dir / filename
        file_size: int = info.get("size", 0)

        try:
            written = extract_file(vmm, vfs_path, local_path, file_size)
            logger.info("  [+] Extracted %s (%d bytes)", filename, written)
            ok += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("  [!] Failed to extract %s: %s", filename, exc)
            errors += 1

    return ok, errors


# ---------------------------------------------------------------------------
# MF-015  Deep artifact extraction ("Total Dump")
# ---------------------------------------------------------------------------

def _vfs_write(vmm: Any, vfs_path: str, local_path: Path) -> int:
    """Read a VFS entry via chunked reads and write to *local_path*.

    Returns the number of bytes written, or ``0`` on failure.  Uses the same
    chunked approach as :func:`extract_file` but derives the size
    automatically from the VFS listing when possible.
    """
    try:
        # Try to get size from the parent listing.
        parent = vfs_path.rsplit("/", 1)[0] + "/"
        name = vfs_path.rsplit("/", 1)[1]
        listing = vmm.vfs.list(parent)
        file_size = listing.get(name, {}).get("size", 0)
    except Exception:  # noqa: BLE001
        file_size = 0

    if file_size > 0:
        return extract_file(vmm, vfs_path, local_path, file_size)

    # Fallback: single bulk read (small files / size unknown).
    data = vmm.vfs.read(vfs_path)
    local_path.write_bytes(data)
    return len(data)


def _extract_registry_hives(vmm: Any, case_dir: Path) -> None:
    """Stage 1 — Extract standard registry hives and NTUSER.DAT files."""
    hive_dir = case_dir / "raw" / "registry"
    hive_dir.mkdir(parents=True, exist_ok=True)

    # Standard system hives
    for hive_name in REGISTRY_HIVES:
        src = f"{VFS_REGISTRY_PATH}{hive_name}"
        dst = hive_dir / hive_name
        try:
            written = _vfs_write(vmm, src, dst)
            logger.info("   [+] Extracted Hive: %s (%d bytes)", hive_name, written)
        except Exception as exc:  # noqa: BLE001
            logger.warning("   [!] Could not extract hive %s: %s", hive_name, exc)

    # NTUSER.DAT files — walk the hive_files directory for any matching name
    try:
        listing = vmm.vfs.list(VFS_REGISTRY_PATH)
        for entry_name in sorted(listing):
            if entry_name.upper().startswith("NTUSER"):
                src = f"{VFS_REGISTRY_PATH}{entry_name}"
                dst = hive_dir / entry_name
                try:
                    written = _vfs_write(vmm, src, dst)
                    logger.info("   [+] Extracted User Hive: %s (%d bytes)", entry_name, written)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("   [!] Could not extract %s: %s", entry_name, exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("   [!] Registry directory listing failed: %s", exc)


def _parse_findevil_malicious_pids(vmm: Any) -> Set[str]:
    """Parse the FindEvil report and return PIDs flagged as malicious.

    The report is a text table.  We look for lines that contain known
    severity keywords (CRITICAL, HIGH, MALICIOUS, ALERT) and try to
    extract the PID field from them.  If the report cannot be read we
    fall back to an empty set, and the caller can still dump LSASS as a
    safety net.
    """
    pids: Set[str] = set()
    try:
        raw = vmm.vfs.read(VFS_FINDEVIL_REPORT)
        text = raw.decode(errors="replace")
        for line in text.splitlines():
            upper = line.upper()
            if not any(kw in upper for kw in ("CRITICAL", "HIGH", "MALICIOUS", "ALERT")):
                continue
            # Try to extract a numeric PID token from the line.
            for token in line.replace(",", " ").replace("|", " ").split():
                if token.isdigit():
                    pids.add(token)
                    break  # first numeric token on flagged line is the PID
    except Exception as exc:  # noqa: BLE001
        logger.warning("   [!] Could not parse FindEvil report for PIDs: %s", exc)
    return pids


def _extract_suspicious_binaries(vmm: Any, case_dir: Path) -> None:
    """Stage 2 — Dump minidumps & open-handle files for malicious PIDs.

    Instead of dumping *every* process (which would rival the image size)
    we only dump those flagged by the FindEvil scanner.  LSASS is always
    included as a credential-theft safety net.
    """
    dump_dir = case_dir / "raw" / "dumps"
    dump_dir.mkdir(parents=True, exist_ok=True)

    files_base = case_dir / "raw" / "files"
    files_base.mkdir(parents=True, exist_ok=True)

    # Collect PIDs to dump — FindEvil flagged + LSASS
    flagged_pids = _parse_findevil_malicious_pids(vmm)
    if flagged_pids:
        logger.info("   [*] FindEvil flagged PIDs: %s", ", ".join(sorted(flagged_pids)))
    else:
        logger.info("   [*] No PIDs flagged by FindEvil — will still target LSASS.")

    # Also discover LSASS PID(s) so we always dump them.
    lsass_pids: Set[str] = set()
    try:
        pid_listing = vmm.vfs.list(VFS_PID_ROOT)
        for pid_str in pid_listing:
            if not pid_str.isdigit():
                continue
            try:
                name_raw = vmm.vfs.read(f"{VFS_PID_ROOT}{pid_str}/name.txt")
                name = name_raw.decode(errors="replace").strip().lower()
                if name == "lsass.exe":
                    lsass_pids.add(pid_str)
            except Exception:  # noqa: BLE001
                continue
    except Exception as exc:  # noqa: BLE001
        logger.warning("   [!] PID directory listing failed: %s", exc)

    if lsass_pids:
        logger.info("   [!] LSASS PID(s) detected: %s", ", ".join(sorted(lsass_pids)))

    target_pids = flagged_pids | lsass_pids

    for pid_str in sorted(target_pids):
        # -- Minidump --------------------------------------------------------- #
        minidump_src = f"{VFS_PID_ROOT}{pid_str}/minidump.dmp"
        minidump_dst = dump_dir / f"pid_{pid_str}.dmp"
        try:
            written = _vfs_write(vmm, minidump_src, minidump_dst)
            logger.info("   [+] Dumped PID %s minidump (%d bytes)", pid_str, written)
        except Exception as exc:  # noqa: BLE001
            logger.warning("   [!] Minidump for PID %s failed: %s", pid_str, exc)

        # -- Open-handle files ------------------------------------------------ #
        handles_src = f"{VFS_PID_ROOT}{pid_str}/files/"
        handles_dst = files_base / f"pid_{pid_str}_files"
        handles_dst.mkdir(parents=True, exist_ok=True)
        try:
            handle_listing = vmm.vfs.list(handles_src)
            for fname in sorted(handle_listing):
                try:
                    src_path = f"{handles_src}{fname}"
                    dst_path = handles_dst / fname
                    _vfs_write(vmm, src_path, dst_path)
                    logger.debug("      [+] Handle file: %s", fname)
                except Exception:  # noqa: BLE001
                    continue
            logger.info(
                "   [+] Copied %d open-handle file(s) for PID %s",
                len(handle_listing),
                pid_str,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("   [!] Open-handle listing for PID %s failed: %s", pid_str, exc)


def _extract_recovered_files(vmm: Any, case_dir: Path) -> None:
    """Stage 3 — Copy carved files that match suspicious extensions."""
    rec_dir = case_dir / "raw" / "recovered_files"
    rec_dir.mkdir(parents=True, exist_ok=True)

    try:
        listing = vmm.vfs.list(VFS_FORENSIC_FILES)
    except Exception as exc:  # noqa: BLE001
        logger.warning("   [!] Forensic file listing failed: %s", exc)
        return

    count = 0
    for fname in sorted(listing):
        if not any(fname.lower().endswith(ext) for ext in RECOVERED_EXTENSIONS):
            continue
        src = f"{VFS_FORENSIC_FILES}{fname}"
        dst = rec_dir / fname
        try:
            written = _vfs_write(vmm, src, dst)
            logger.info("   [+] Recovered binary: %s (%d bytes)", fname, written)
            count += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("   [!] Failed to recover %s: %s", fname, exc)

    logger.info("   [*] Recovered %d suspicious file(s) total.", count)


def _capture_findevil_report(vmm: Any, case_dir: Path) -> None:
    """Stage 4 — Copy the raw FindEvil text report to ``<case>/docs/``."""
    docs_dir = case_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    dst = docs_dir / "findevil_raw.txt"
    try:
        written = _vfs_write(vmm, VFS_FINDEVIL_REPORT, dst)
        logger.info("   [+] FindEvil report saved (%d bytes) → %s", written, dst)
    except Exception as exc:  # noqa: BLE001
        logger.warning("   [!] Could not capture FindEvil report: %s", exc)


def perform_deep_extraction(vmm: Any, case_dir: Path) -> None:
    """MF-015 — Full scene-clone ("Total Dump") extraction.

    Orchestrates four independent extraction stages:

    1. **Registry hives** — SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT.
    2. **Suspicious process dumps** — minidumps + open handles for PIDs
       flagged by FindEvil, plus LSASS.
    3. **Recovered executables** — carved ``.exe/.dll/.ps1/.bat/.sys``.
    4. **FindEvil report** — verbatim ``findevil.txt``.

    Each stage is isolated; a failure in one does not abort the others.
    """
    print("\n[!!!] STARTING DEEP ARTIFACT EXTRACTION (MF-015) [!!!]")
    logger.info("Deep extraction target: %s", case_dir)

    # Stage 1 — Registry Hives
    logger.info("[Stage 1/4] Extracting registry hives …")
    _extract_registry_hives(vmm, case_dir)

    # Stage 2 — Suspicious Process Binaries (Smart Dump)
    logger.info("[Stage 2/4] Dumping suspicious processes …")
    _extract_suspicious_binaries(vmm, case_dir)

    # Stage 3 — Recovered Files
    logger.info("[Stage 3/4] Recovering carved binaries …")
    _extract_recovered_files(vmm, case_dir)

    # Stage 4 — FindEvil Report
    logger.info("[Stage 4/4] Capturing FindEvil report …")
    _capture_findevil_report(vmm, case_dir)

    print("[!!!] DEEP EXTRACTION COMPLETE [!!!]\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract.

    ``--device`` replaces the standard ``--in`` argument because the input
    is a raw memory dump, not a CSV file or directory.
    """
    parser = argparse.ArgumentParser(
        prog="memflow_ingest",
        description="MF-010: Extract raw CSVs from a MemProcFS memory dump.",
    )
    parser.add_argument(
        "--case", "-c",
        required=True,
        type=Path,
        help="Path to the investigation root directory.",
    )
    parser.add_argument(
        "--device", "-d",
        required=True,
        type=Path,
        help="Path to the raw memory dump file (e.g. mem.raw, mem.dmp).",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for extracted CSVs (default: <case>/csv/).",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--wait", "-w",
        type=int,
        default=DEFAULT_INIT_WAIT_SECONDS,
        help=(
            "Maximum seconds to wait for the forensic engine to populate "
            f"the CSV directory (default: {DEFAULT_INIT_WAIT_SECONDS})."
        ),
    )
    parser.add_argument(
        "--full-dump",
        action="store_true",
        default=False,
        help=(
            "MF-015: Perform deep artifact extraction (registry hives, "
            "suspicious process dumps, recovered binaries, FindEvil report). "
            "WARNING — this can use disk space ~2x the RAM image size."
        ),
    )
    parser.add_argument(
        "--memprocfs-exe",
        type=Path,
        default=None,
        help="Path to MemProcFS.exe (for fallback when Python API fails).",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns an exit code (0 = OK, 1 = partial, 2 = fatal)."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # -- Logging ------------------------------------------------------------ #
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # -- Dependency check --------------------------------------------------- #
    if memprocfs is None:
        logger.error(
            "The 'memprocfs' package is not installed.  "
            "Install it with:  pip install memprocfs",
        )
        return 2

    # -- Resolve paths ------------------------------------------------------ #
    case_dir: Path = args.case.resolve()
    device_path: Path = args.device.resolve()
    out_dir: Path = (args.out or (case_dir / "csv")).resolve()

    # -- Startup validation ------------------------------------------------- #
    if not device_path.is_file():
        logger.error("Memory dump not found or not a file: %s", device_path)
        return 2

    if not case_dir.exists():
        logger.warning("Case directory does not exist — creating: %s", case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    # -- Initialise MemProcFS forensic engine ------------------------------- #
    logger.info("Initialising MemProcFS forensic engine on %s …", device_path)

    _vmm_args = [
        "-device", str(device_path),
        "-forensic", "1",
        "-forensic-scan-ranges", "1",
        "-csv",
    ]

    vmm = None
    try:
        vmm = memprocfs.Vmm(_vmm_args)
    except Exception as exc:  # noqa: BLE001
        logger.warning("MemProcFS Python API failed: %s", exc)
        ok, errors = _extract_via_memprocfs_exe(
            device_path, out_dir, args.wait,
            memprocfs_exe=getattr(args, "memprocfs_exe", None),
        )
        if ok == 0 and errors > 0:
            logger.error("MemProcFS.exe fallback also failed.")
            return 2
        if args.full_dump:
            logger.warning(
                "Full-dump mode not supported when using MemProcFS.exe fallback. "
                "Only CSV extraction was performed."
            )
    else:
        # -- Wait for CSV generation ---------------------------------------- #
        if not wait_for_csv_directory(vmm, wait_seconds=args.wait):
            logger.error(
                "Forensic CSV directory (%s) did not appear within %d s. "
                "The memory image may be corrupt or the forensic scan may need "
                "more time (try increasing --wait).",
                VFS_CSV_PATH,
                args.wait,
            )
            return 2

        # -- Extract all CSVs ----------------------------------------------- #
        ok, errors = extract_all_csvs(vmm, out_dir)

        # -- MF-015  Deep extraction (--full-dump) -------------------------- #
        if args.full_dump:
            logger.info(
                "Full-dump mode enabled — starting deep artifact extraction …"
            )
            perform_deep_extraction(vmm, case_dir)

    # -- Summary & exit code ------------------------------------------------ #
    logger.info(
        "Extraction complete: %d CSV(s) succeeded, %d failed.  Output → %s",
        ok,
        errors,
        out_dir,
    )
    if args.full_dump and vmm is not None:
        logger.info(
            "Deep artifacts written under: %s/raw/ and %s/docs/",
            case_dir,
            case_dir,
        )

    if ok == 0 and errors > 0:
        return 2   # Total failure — nothing was extracted.
    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

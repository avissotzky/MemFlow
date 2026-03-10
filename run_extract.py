"""MemFlow Extract — plugin-based orchestrator.

Opens a single MemProcFS VMM session against a memory dump, enables
forensic mode, then auto-discovers and runs every extractor plugin
found in the ``extractors/`` package.

Usage
-----
::

    # Run all extractors
    python run_extract.py --dump MEMORY.DMP --case case_demo

    # Run only specific abilities
    python run_extract.py --dump MEMORY.DMP --case case_demo --only processes,dlls,netstat

    # Run everything except timelines
    python run_extract.py --dump MEMORY.DMP --case case_demo --exclude timelines

    # List available extractors without running anything
    python run_extract.py --list
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import memprocfs
except ImportError:
    memprocfs = None

from extractors import discover_extractors
from extractors.base import ExtractResult

logger = logging.getLogger(__name__)

FORENSIC_ENABLE_PATH = "/forensic/forensic_enable.txt"
FORENSIC_PROGRESS_PATH = "/forensic/progress_percent.txt"
FORENSIC_CSV_PATH = "/forensic/csv/"
DEFAULT_TIMEOUT = 300
POLL_INTERVAL = 5


# ---------------------------------------------------------------------------
# Forensic mode helpers
# ---------------------------------------------------------------------------

def enable_forensic_mode(vmm: Any, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Enable the forensic scanner and block until CSVs appear."""
    logger.info("Enabling forensic scan via VFS …")
    try:
        vmm.vfs.write(FORENSIC_ENABLE_PATH, b"1", 0)
    except Exception as exc:
        logger.error("Could not enable forensic mode: %s", exc)
        return False

    deadline = time.monotonic() + timeout
    last_progress = ""
    while time.monotonic() < deadline:
        try:
            prog = vmm.vfs.read(FORENSIC_PROGRESS_PATH, 100, 0)
            prog_str = prog.decode(errors="replace").strip()
            if prog_str != last_progress:
                logger.info("  Forensic progress: %s%%", prog_str)
                last_progress = prog_str
        except Exception:
            pass

        try:
            listing = vmm.vfs.list(FORENSIC_CSV_PATH)
            if listing:
                logger.info(
                    "  Forensic CSV directory ready (%d files)", len(listing),
                )
                return True
        except Exception:
            pass

        time.sleep(POLL_INTERVAL)

    logger.error("Forensic CSVs did not appear within %d s.", timeout)
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_extract",
        description="MemFlow Extract — plugin-based memory dump extractor.",
    )
    parser.add_argument(
        "--dump", "-d",
        type=Path,
        help="Path to the raw memory dump file.",
    )
    parser.add_argument(
        "--case", "-c",
        type=Path,
        help="Investigation root directory.",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for CSVs (default: <case>/csv/).",
    )
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help="Comma-separated list of extractor names to run (e.g. processes,dlls).",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        help="Comma-separated list of extractor names to skip.",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Seconds to wait for forensic CSV generation (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        default=False,
        help="List all discovered extractors and exit.",
    )
    return parser


def resolve_extractors(
    registry: Dict[str, Any],
    only: Optional[str],
    exclude: Optional[str],
) -> Dict[str, Any]:
    """Filter the extractor registry by --only / --exclude flags."""
    if only:
        names = {n.strip() for n in only.split(",")}
        unknown = names - set(registry)
        if unknown:
            logger.warning("Unknown extractor(s) in --only: %s", ", ".join(sorted(unknown)))
        return {k: v for k, v in registry.items() if k in names}

    if exclude:
        names = {n.strip() for n in exclude.split(",")}
        return {k: v for k, v in registry.items() if k not in names}

    return registry


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # -- Discover all extractors ------------------------------------------- #
    registry = discover_extractors()

    if args.list:
        print("Available extractors:")
        for name, cls in registry.items():
            print(f"  {name:24s}  source={cls.source:14s}  -> {cls.output_filename}")
        return 0

    # -- Validate required args -------------------------------------------- #
    if not args.dump or not args.case:
        parser.error("--dump and --case are required (unless using --list).")

    if memprocfs is None:
        logger.error("The 'memprocfs' package is not installed.  pip install memprocfs")
        return 2

    dump_path: Path = args.dump.resolve()
    case_dir: Path = args.case.resolve()
    out_dir: Path = (args.out or (case_dir / "csv")).resolve()

    if not dump_path.is_file():
        logger.error("Dump file not found: %s", dump_path)
        return 2

    case_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = resolve_extractors(registry, args.only, args.exclude)
    if not selected:
        logger.error("No extractors selected after filtering.")
        return 2

    # -- Check if any extractor needs forensic CSVs ------------------------ #
    needs_forensic = any(cls.source == "forensic_csv" for cls in selected.values())

    # -- Initialise VMM ---------------------------------------------------- #
    print("=" * 60)
    print("MemFlow Extract — Plugin Orchestrator")
    print("=" * 60)
    print(f"Dump:       {dump_path}")
    print(f"Case:       {case_dir}")
    print(f"Output:     {out_dir}")
    print(f"Extractors: {', '.join(selected)}")
    print()

    logger.info("Initialising MemProcFS …")
    vmm = memprocfs.Vmm(["-device", str(dump_path)])
    proc_count = len(vmm.process_list())
    logger.info("VMM OK — %d processes detected", proc_count)

    # -- Enable forensic mode if needed ------------------------------------ #
    forensic_ok = True
    if needs_forensic:
        forensic_ok = enable_forensic_mode(vmm, timeout=args.timeout)
        if not forensic_ok:
            logger.warning(
                "Forensic mode failed — forensic_csv extractors will be skipped."
            )

    # -- Run each extractor ------------------------------------------------ #
    results: Dict[str, ExtractResult] = {}
    for name, cls in selected.items():
        if cls.source == "forensic_csv" and not forensic_ok:
            results[name] = ExtractResult(ok=False, error="forensic mode unavailable")
            logger.warning("  SKIP  %-24s (forensic mode unavailable)", name)
            continue

        logger.info("  RUN   %-24s (source=%s)", name, cls.source)
        try:
            extractor = cls()
            result = extractor.extract(vmm, out_dir)
            results[name] = result
            status = "OK" if result.ok else "FAIL"
            logger.info(
                "  %-4s  %-24s  %d rows  %s",
                status, name, result.rows,
                ", ".join(result.files_written) if result.files_written else "",
            )
        except Exception as exc:
            results[name] = ExtractResult(ok=False, error=str(exc))
            logger.error("  FAIL  %-24s  %s", name, exc)

    vmm.close()

    # -- Summary ----------------------------------------------------------- #
    print()
    print("=" * 60)
    print("Extraction Summary")
    print("=" * 60)
    ok_count = sum(1 for r in results.values() if r.ok)
    fail_count = sum(1 for r in results.values() if not r.ok)
    total_rows = sum(r.rows for r in results.values())

    for name, r in results.items():
        tag = "OK  " if r.ok else "FAIL"
        detail = f"{r.rows} rows" if r.ok else (r.error or "unknown error")
        print(f"  [{tag}] {name:24s}  {detail}")

    print()
    print(f"  Succeeded: {ok_count}  |  Failed: {fail_count}  |  Total rows: {total_rows}")
    print(f"  Output: {out_dir}")
    print("=" * 60)

    return 1 if fail_count > 0 and ok_count > 0 else (2 if ok_count == 0 and fail_count > 0 else 0)


if __name__ == "__main__":
    sys.exit(main())

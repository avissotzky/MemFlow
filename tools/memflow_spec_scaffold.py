"""
tools.memflow_spec_scaffold
============================
**MF-030 — Spec Scaffold Generator.**

Reads the CSV inventory JSON (``<case>/docs/03_csv_inventory.json``) and
generates initial YAML spec files for every discovered table that does not
yet have a spec.

Each generated spec follows the template::

    table: <filename>
    columns:
      <col>: { type: "raw" }  # To be filled later
    validations: []

Usage
-----
::

    python -m tools.memflow_spec_scaffold --case C:\\Cases\\IR-2025-042

"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# YAML generation (stdlib-only — no PyYAML dependency)
# ---------------------------------------------------------------------------

def build_yaml_spec(filename: str, headers: List[str]) -> str:
    """Build a YAML spec string for a single table.

    We write YAML by hand to avoid adding a PyYAML dependency.
    The format is deliberately simple and deterministic.
    """
    lines: List[str] = []
    lines.append(f"table: {filename}")
    lines.append("columns:")

    if headers:
        for col in headers:
            safe_col = col
            # Quote the column name if it contains characters that are
            # special in YAML (colon, braces, etc.).
            if any(ch in col for ch in ":{},[]&*?|>!%@`#'\"\\"):
                safe_col = f'"{col}"'
            lines.append(f'  {safe_col}: {{ type: "raw" }}  # To be filled later')
    else:
        lines.append("  {}  # No headers detected")

    lines.append("validations: []")
    lines.append("")  # trailing newline
    return "\n".join(lines)


def table_name_from_filename(filename: str) -> str:
    """Derive the YAML spec stem from a CSV filename.

    ``process.csv``  →  ``process``
    ``my_data.csv``  →  ``my_data``
    """
    return Path(filename).stem


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def generate_specs(
    inventory: Dict[str, Any],
    specs_dir: Path,
    *,
    overwrite: bool = False,
) -> Dict[str, str]:
    """Generate YAML spec scaffolds for every table in *inventory*.

    Parameters
    ----------
    inventory : dict
        Parsed ``03_csv_inventory.json``.
    specs_dir : Path
        Target directory for ``.yaml`` files.
    overwrite : bool
        If ``True``, regenerate even when a spec already exists.

    Returns
    -------
    dict
        Mapping of table name → action:
        ``"created"``, ``"skipped"``, or ``"skipped_no_headers"``.
    """
    specs_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, str] = {}

    for entry in inventory.get("files", []):
        filename: str = entry["filename"]
        headers: List[str] = entry.get("headers", [])
        table_name = table_name_from_filename(filename)
        spec_path = specs_dir / f"{table_name}.yaml"

        # Skip files that have no headers (completely empty / broken)
        if not headers:
            logger.info("Skipping %s — no headers detected.", filename)
            results[table_name] = "skipped_no_headers"
            continue

        # Skip if spec already exists (unless overwrite is requested)
        if spec_path.exists() and not overwrite:
            logger.info("Spec already exists: %s — skipping.", spec_path.name)
            results[table_name] = "skipped"
            continue

        # Generate and write
        yaml_content = build_yaml_spec(filename, headers)
        spec_path.write_text(yaml_content, encoding="utf-8")
        logger.info("Created spec: %s", spec_path.name)
        results[table_name] = "created"

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser following the MemFlow CLI contract."""
    parser = argparse.ArgumentParser(
        prog="memflow_spec_scaffold",
        description="MF-030: Generate initial YAML specs for discovered CSV tables.",
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
        help="Path to the inventory JSON (default: <case>/docs/03_csv_inventory.json).",
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        default=None,
        help="Output directory for YAML specs (default: memflow_specs/).",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Overwrite existing spec files.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.  Returns 0 on success, 2 on fatal errors."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # -- Logging ------------------------------------------------------------ #
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    case_dir: Path = args.case.resolve()
    in_path: Path = (
        args.in_path
        or (case_dir / "docs" / "03_csv_inventory.json")
    ).resolve()
    specs_dir: Path = (args.out or Path("memflow_specs")).resolve()

    # -- Validate ----------------------------------------------------------- #
    if not in_path.is_file():
        logger.error("Inventory JSON not found: %s", in_path)
        logger.error("Run memflow_inventory first to generate the inventory.")
        return 2

    # -- Load inventory ----------------------------------------------------- #
    try:
        with in_path.open("r", encoding="utf-8") as fh:
            inventory = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to load inventory JSON: %s", exc)
        return 2

    # -- Generate specs ----------------------------------------------------- #
    results = generate_specs(inventory, specs_dir, overwrite=args.overwrite)

    created = sum(1 for v in results.values() if v == "created")
    skipped = sum(1 for v in results.values() if v == "skipped")
    no_headers = sum(1 for v in results.values() if v == "skipped_no_headers")

    logger.info(
        "Spec generation complete: %d created, %d skipped (existing), "
        "%d skipped (no headers).",
        created, skipped, no_headers,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())

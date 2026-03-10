"""
memflow_parser.engine
=====================
**MF-040 — The Parser Engine (Core Logic).**

Converts a Raw CSV (all-string ``RawTable``) into a Typed CSV by applying a
YAML Spec that declares the expected type for every column.

This is a **library**, not a script.  Entry-point tools live in ``tools/``.

Design constraints
------------------
- The **output row count must equal the input row count**.  No row is ever
  dropped during parsing.
- On conversion failure the raw value is preserved as-is (string) and a
  :class:`ParseError` is appended to the error log.
- Zero external dependencies — the simple YAML spec format is parsed with
  stdlib only (no PyYAML).

Supported column types
----------------------
``raw`` / ``string``
    No conversion; value kept as-is.
``int``
    Decimal integer (``"123"`` → ``"123"``).  Strips whitespace.
``hex_int``
    Hex string → decimal integer (``"0x1A"`` → ``"26"``).
``float``
    Floating-point number (``"3.14"`` → ``"3.14"``).
``bool``
    Boolean (``true/false/yes/no/1/0`` → ``"True"`` / ``"False"``).
``timestamp``
    Date/time string → ISO 8601 (``"2024/01/15 10:30:00"`` → ``"2024-01-15T10:30:00"``).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

ErrorLog = List["ParseError"]


@dataclass
class ParseError:
    """A single type-conversion failure captured during parsing."""

    row_index: int          # 0-based index into data rows
    column: str             # Column name
    raw_value: str          # The original value that could not be converted
    expected_type: str      # The target type declared in the spec
    error: str              # Human-readable description of the failure


@dataclass
class ColumnSpec:
    """Definition of a single column from the YAML spec."""

    name: str
    type: str               # "raw", "string", "int", "hex_int", "float", "bool", "timestamp"


@dataclass
class TableSpec:
    """Parsed representation of a YAML spec file."""

    table: str              # Original filename (e.g. "process.csv")
    columns: Dict[str, ColumnSpec] = field(default_factory=dict)
    validations: list = field(default_factory=list)


@dataclass
class TypedTable:
    """The result of parsing a RawTable through a Spec.

    All cell values are still strings (because the final output is CSV), but
    they have been validated and normalised according to the column type.

    Attributes
    ----------
    source_path : Path | None
        The raw CSV that was parsed.
    spec_path : Path | None
        The YAML spec that was applied.
    table_name : str
        Logical table name (e.g. ``"process"``).
    headers : list[str]
        Column names (same order as the raw CSV).
    rows : list[list[str]]
        Data rows with normalised values.
    parse_errors : list[ParseError]
        Every conversion failure encountered.
    input_row_count : int
        Number of data rows in the source RawTable.
    """

    source_path: Optional[Path] = None
    spec_path: Optional[Path] = None
    table_name: str = ""
    headers: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    parse_errors: List[ParseError] = field(default_factory=list)
    input_row_count: int = 0

    # Convenience ---------------------------------------------------------- #

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def column_count(self) -> int:
        return len(self.headers)

    def to_raw_table(self) -> RawTable:
        """Convert back to a :class:`RawTable` for ``write_csv_safe``."""
        return RawTable(
            source_path=self.source_path,
            headers=list(self.headers),
            rows=[list(row) for row in self.rows],
        )

    def __repr__(self) -> str:
        return (
            f"TypedTable(table={self.table_name!r}, "
            f"cols={self.column_count}, rows={self.row_count}, "
            f"errors={len(self.parse_errors)})"
        )


# ---------------------------------------------------------------------------
# YAML spec parser (stdlib-only, no PyYAML)
# ---------------------------------------------------------------------------

# Regex for a column line:   name: { type: "typename" }  # optional comment
# Also handles quoted column names:  "col:name": { type: "typename" }
_COL_RE = re.compile(
    r"""
    ^\s+                           # leading indent
    (?:"([^"]+)"|(\S+))            # column name — quoted or bare
    \s*:\s*                        # colon separator
    \{\s*type\s*:\s*"([^"]+)"\s*\} # { type: "typename" }
    """,
    re.VERBOSE,
)


def load_spec(yaml_path: Path | str) -> TableSpec:
    """Parse a MemFlow YAML spec file into a :class:`TableSpec`.

    Parameters
    ----------
    yaml_path : Path or str
        Path to the ``.yaml`` file.

    Returns
    -------
    TableSpec

    Raises
    ------
    FileNotFoundError
        If the YAML file does not exist.
    ValueError
        If the file cannot be parsed.
    """
    yaml_path = Path(yaml_path)
    logger.info("Loading spec: %s", yaml_path)
    text = yaml_path.read_text(encoding="utf-8")

    spec = TableSpec(table="")

    for line in text.splitlines():
        stripped = line.strip()

        # Skip blank lines and comments.
        if not stripped or stripped.startswith("#"):
            continue

        # table: <name>
        if stripped.startswith("table:"):
            spec.table = stripped.split(":", 1)[1].strip()
            continue

        # validations: []
        if stripped.startswith("validations:"):
            continue

        # columns: (section header — no value)
        if stripped == "columns:":
            continue

        # Column definition line
        match = _COL_RE.match(line)
        if match:
            col_name = match.group(1) or match.group(2)
            col_type = match.group(3)
            spec.columns[col_name] = ColumnSpec(name=col_name, type=col_type)
            continue

        # Catch empty-columns marker: {}  # No headers detected
        if stripped.startswith("{}"):
            continue

        logger.debug("Ignoring unrecognised spec line: %s", stripped)

    if not spec.table:
        raise ValueError(f"Spec file has no 'table:' declaration: {yaml_path}")

    logger.info(
        "Loaded spec for '%s' — %d column(s) defined.",
        spec.table,
        len(spec.columns),
    )
    return spec


# ---------------------------------------------------------------------------
# Type converters
# ---------------------------------------------------------------------------

# Timestamp formats to try (most specific first).
_TIMESTAMP_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%f",       # ISO with fractional seconds
    "%Y-%m-%dT%H:%M:%S",          # ISO
    "%Y-%m-%d %H:%M:%S.%f",       # space-separated with fractional
    "%Y-%m-%d %H:%M:%S",          # space-separated
    "%Y/%m/%d %H:%M:%S",          # slash-separated
    "%m/%d/%Y %H:%M:%S",          # US date-month
    "%d/%m/%Y %H:%M:%S",          # European day-month
    "%Y-%m-%d",                    # Date only
    "%m/%d/%Y",                    # US date only
)

_TRUTHY = frozenset({"true", "yes", "1"})
_FALSY = frozenset({"false", "no", "0"})


def _convert_int(value: str) -> str:
    """Convert a decimal integer string.  Returns the normalised form."""
    return str(int(value.strip()))


def _convert_hex_int(value: str) -> str:
    """Convert a hexadecimal string (``0x…`` or plain hex) to decimal."""
    stripped = value.strip()
    return str(int(stripped, 16))


def _convert_float(value: str) -> str:
    """Convert a float string.  Returns the normalised form."""
    return str(float(value.strip()))


def _convert_bool(value: str) -> str:
    """Convert a boolean string (true/false/yes/no/1/0)."""
    lower = value.strip().lower()
    if lower in _TRUTHY:
        return "True"
    if lower in _FALSY:
        return "False"
    raise ValueError(f"Cannot interpret as boolean: {value!r}")


def _convert_timestamp(value: str) -> str:
    """Convert a date/time string to ISO 8601 format.

    Tries common forensic timestamp formats.  Also handles Unix epoch
    (integer seconds since 1970).
    """
    stripped = value.strip()

    # Try Unix epoch (integer seconds)
    try:
        epoch = int(stripped)
        # Heuristic: values > 1_000_000_000_000 are likely milliseconds.
        if epoch > 1_000_000_000_000:
            epoch_sec = epoch / 1000
        else:
            epoch_sec = epoch
        dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, OverflowError, OSError):
        pass

    # Try standard datetime formats
    for fmt in _TIMESTAMP_FMTS:
        try:
            dt = datetime.strptime(stripped, fmt)
            return dt.isoformat()
        except ValueError:
            continue

    raise ValueError(f"Cannot parse timestamp: {value!r}")


_CONVERTERS = {
    "raw": None,
    "string": None,
    "int": _convert_int,
    "hex_int": _convert_hex_int,
    "float": _convert_float,
    "bool": _convert_bool,
    "timestamp": _convert_timestamp,
}


def convert_value(value: str, target_type: str) -> Tuple[str, Optional[str]]:
    """Attempt to convert *value* to *target_type*.

    Parameters
    ----------
    value : str
        The raw cell value.
    target_type : str
        One of the supported type names (``"int"``, ``"hex_int"``, etc.).

    Returns
    -------
    tuple[str, str | None]
        ``(converted_value, error_message)``.
        On success *error_message* is ``None``.
        On failure *converted_value* is the original *value* unchanged.
    """
    # Empty / whitespace-only cells — keep as-is, no error.
    if not value or not value.strip():
        return value, None

    converter = _CONVERTERS.get(target_type)
    if converter is None:
        # "raw" / "string" or unknown type with no converter → passthrough.
        return value, None

    try:
        converted = converter(value)
        return converted, None
    except (ValueError, TypeError, OverflowError) as exc:
        return value, str(exc)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_table(
    raw_csv_path: Path | str,
    spec_yaml_path: Path | str,
) -> Tuple[TypedTable, ErrorLog]:
    """Parse a raw CSV through a YAML spec, producing a typed table.

    Parameters
    ----------
    raw_csv_path : Path or str
        Path to the raw (all-string) CSV file.
    spec_yaml_path : Path or str
        Path to the YAML spec file that defines column types.

    Returns
    -------
    tuple[TypedTable, ErrorLog]
        The typed table and a list of every conversion error encountered.
        **The output row count always equals the input row count.**
    """
    raw_csv_path = Path(raw_csv_path)
    spec_yaml_path = Path(spec_yaml_path)

    # -- Load raw data ------------------------------------------------------ #
    raw_table: RawTable = read_csv_safe(raw_csv_path)

    # -- Load spec ---------------------------------------------------------- #
    spec: TableSpec = load_spec(spec_yaml_path)

    # -- Prepare output ----------------------------------------------------- #
    table_name = Path(spec.table).stem
    typed = TypedTable(
        source_path=raw_csv_path,
        spec_path=spec_yaml_path,
        table_name=table_name,
        headers=list(raw_table.headers),
        input_row_count=raw_table.row_count,
    )
    errors: ErrorLog = []

    # Build a column-index → ColumnSpec mapping for fast lookup.
    col_specs: Dict[int, ColumnSpec] = {}
    for idx, header in enumerate(raw_table.headers):
        if header in spec.columns:
            col_specs[idx] = spec.columns[header]

    # -- Iterate rows ------------------------------------------------------- #
    for row_idx, raw_row in enumerate(raw_table.rows):
        typed_row: List[str] = []

        for col_idx, cell in enumerate(raw_row):
            if col_idx in col_specs:
                col_spec = col_specs[col_idx]
                converted, err_msg = convert_value(cell, col_spec.type)

                if err_msg is not None:
                    pe = ParseError(
                        row_index=row_idx,
                        column=raw_table.headers[col_idx],
                        raw_value=cell,
                        expected_type=col_spec.type,
                        error=err_msg,
                    )
                    errors.append(pe)
                    typed.parse_errors.append(pe)
                    logger.debug(
                        "Row %d, col '%s': %s",
                        row_idx,
                        raw_table.headers[col_idx],
                        err_msg,
                    )
                    # Keep raw value on failure.
                    typed_row.append(cell)
                else:
                    typed_row.append(converted)
            else:
                # Column not in spec — pass through unchanged.
                typed_row.append(cell)

        typed.rows.append(typed_row)

    # -- Invariant check ---------------------------------------------------- #
    assert typed.row_count == typed.input_row_count, (
        f"Row count invariant violated: input={typed.input_row_count}, "
        f"output={typed.row_count}"
    )

    logger.info(
        "Parsed '%s': %d rows, %d conversion error(s).",
        table_name,
        typed.row_count,
        len(errors),
    )
    return typed, errors

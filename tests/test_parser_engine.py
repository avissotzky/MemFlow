"""
tests.test_parser_engine
=========================
Unit tests for :mod:`memflow_parser.engine` (MF-040) and
:mod:`tools.memflow_parse_generic` (MF-050).

Key acceptance criteria
-----------------------
- A "Bad Integer" in the input results in a logged error **but the row is
  preserved** in the output.
- Output row count **always** equals input row count (the lossless invariant).
- All supported type conversions produce correct normalised values.
- The CLI tool writes ``typed_<table>.csv`` and ``_parsing_errors.csv``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from memflow_parser.engine import (
    ColumnSpec,
    TableSpec,
    TypedTable,
    convert_value,
    load_spec,
    parse_table,
)
from tools.memflow_parse_generic import (
    find_spec_for_csv,
    main,
    write_parsing_errors,
)


# ── Helpers ────────────────────────────────────────────────────────────── #


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Shorthand for pytest-provided temp directory."""
    return tmp_path


def _write_csv(path: Path, content: str) -> Path:
    """Write a CSV string to *path*, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_spec(path: Path, table: str, columns: dict[str, str]) -> Path:
    """Write a minimal YAML spec file."""
    lines = [f"table: {table}", "columns:"]
    for col, ctype in columns.items():
        lines.append(f'  {col}: {{ type: "{ctype}" }}')
    lines.append("validations: []")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ═══════════════════════════════════════════════════════════════════════════
# 1. convert_value — individual type conversions
# ═══════════════════════════════════════════════════════════════════════════


class TestConvertValueRawString:
    """Raw / string types pass through unchanged."""

    def test_raw_passthrough(self):
        val, err = convert_value("hello", "raw")
        assert val == "hello"
        assert err is None

    def test_string_passthrough(self):
        val, err = convert_value("world", "string")
        assert val == "world"
        assert err is None

    def test_empty_string(self):
        val, err = convert_value("", "int")
        assert val == ""
        assert err is None

    def test_whitespace_only(self):
        val, err = convert_value("   ", "int")
        assert val == "   "
        assert err is None


class TestConvertValueInt:
    """Decimal integer conversion."""

    def test_simple(self):
        val, err = convert_value("42", "int")
        assert val == "42"
        assert err is None

    def test_negative(self):
        val, err = convert_value("-7", "int")
        assert val == "-7"
        assert err is None

    def test_with_whitespace(self):
        val, err = convert_value("  123  ", "int")
        assert val == "123"
        assert err is None

    def test_bad_integer_returns_error(self):
        val, err = convert_value("not_a_number", "int")
        assert val == "not_a_number"  # raw value preserved
        assert err is not None
        assert "invalid literal" in err

    def test_float_string_is_not_int(self):
        val, err = convert_value("3.14", "int")
        assert val == "3.14"
        assert err is not None


class TestConvertValueHexInt:
    """Hex string → decimal integer conversion."""

    def test_prefixed_hex(self):
        val, err = convert_value("0x1A", "hex_int")
        assert val == "26"
        assert err is None

    def test_uppercase(self):
        val, err = convert_value("0xFF", "hex_int")
        assert val == "255"
        assert err is None

    def test_no_prefix(self):
        val, err = convert_value("ff", "hex_int")
        assert val == "255"
        assert err is None

    def test_bad_hex(self):
        val, err = convert_value("0xGG", "hex_int")
        assert val == "0xGG"
        assert err is not None


class TestConvertValueFloat:
    """Float conversion."""

    def test_simple(self):
        val, err = convert_value("3.14", "float")
        assert val == "3.14"
        assert err is None

    def test_integer_as_float(self):
        val, err = convert_value("42", "float")
        assert val == "42.0"
        assert err is None

    def test_bad_float(self):
        val, err = convert_value("abc", "float")
        assert val == "abc"
        assert err is not None


class TestConvertValueBool:
    """Boolean conversion."""

    def test_true_variants(self):
        for s in ("true", "True", "TRUE", "yes", "YES", "1"):
            val, err = convert_value(s, "bool")
            assert val == "True", f"Failed for {s!r}"
            assert err is None

    def test_false_variants(self):
        for s in ("false", "False", "FALSE", "no", "NO", "0"):
            val, err = convert_value(s, "bool")
            assert val == "False", f"Failed for {s!r}"
            assert err is None

    def test_bad_bool(self):
        val, err = convert_value("maybe", "bool")
        assert val == "maybe"
        assert err is not None


class TestConvertValueTimestamp:
    """Timestamp / datetime conversion."""

    def test_iso_format(self):
        val, err = convert_value("2024-01-15T10:30:00", "timestamp")
        assert val == "2024-01-15T10:30:00"
        assert err is None

    def test_space_separated(self):
        val, err = convert_value("2024-01-15 10:30:00", "timestamp")
        assert val == "2024-01-15T10:30:00"
        assert err is None

    def test_slash_separated(self):
        val, err = convert_value("2024/01/15 10:30:00", "timestamp")
        assert val == "2024-01-15T10:30:00"
        assert err is None

    def test_date_only(self):
        val, err = convert_value("2024-01-15", "timestamp")
        assert val == "2024-01-15T00:00:00"
        assert err is None

    def test_unix_epoch(self):
        val, err = convert_value("1705312200", "timestamp")
        assert err is None
        assert val.startswith("2024-01-15")

    def test_bad_timestamp(self):
        val, err = convert_value("not-a-date", "timestamp")
        assert val == "not-a-date"
        assert err is not None


# ═══════════════════════════════════════════════════════════════════════════
# 2. load_spec — YAML spec parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadSpec:
    """Loading and parsing YAML spec files."""

    def test_basic_spec(self, tmp: Path):
        spec_path = _write_spec(
            tmp / "process.yaml", "process.csv",
            {"pid": "int", "name": "string", "ppid": "int"},
        )
        spec = load_spec(spec_path)

        assert spec.table == "process.csv"
        assert len(spec.columns) == 3
        assert spec.columns["pid"].type == "int"
        assert spec.columns["name"].type == "string"
        assert spec.columns["ppid"].type == "int"

    def test_quoted_column_names(self, tmp: Path):
        content = (
            'table: weird.csv\n'
            'columns:\n'
            '  "has:colon": { type: "raw" }\n'
            '  normal: { type: "int" }\n'
            'validations: []\n'
        )
        spec_path = tmp / "weird.yaml"
        spec_path.write_text(content, encoding="utf-8")

        spec = load_spec(spec_path)
        assert "has:colon" in spec.columns
        assert spec.columns["has:colon"].type == "raw"
        assert spec.columns["normal"].type == "int"

    def test_comments_ignored(self, tmp: Path):
        content = (
            '# This is a comment\n'
            'table: data.csv\n'
            'columns:\n'
            '  val: { type: "int" }  # inline comment\n'
            'validations: []\n'
        )
        spec_path = tmp / "data.yaml"
        spec_path.write_text(content, encoding="utf-8")

        spec = load_spec(spec_path)
        assert spec.table == "data.csv"
        assert spec.columns["val"].type == "int"

    def test_missing_table_raises(self, tmp: Path):
        content = 'columns:\n  x: { type: "raw" }\nvalidations: []\n'
        spec_path = tmp / "bad.yaml"
        spec_path.write_text(content, encoding="utf-8")

        with pytest.raises(ValueError, match="no 'table:' declaration"):
            load_spec(spec_path)

    def test_missing_file_raises(self, tmp: Path):
        with pytest.raises(FileNotFoundError):
            load_spec(tmp / "nonexistent.yaml")


# ═══════════════════════════════════════════════════════════════════════════
# 3. parse_table — the core engine
# ═══════════════════════════════════════════════════════════════════════════


class TestParseTableCleanData:
    """All values convert successfully — no errors."""

    def test_all_columns_typed(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "data.csv",
            "pid,name,active\n1,init,true\n2,kthread,false\n",
        )
        spec_path = _write_spec(
            tmp / "data.yaml", "data.csv",
            {"pid": "int", "name": "string", "active": "bool"},
        )

        typed, errors = parse_table(csv_path, spec_path)

        assert typed.row_count == 2
        assert typed.input_row_count == 2
        assert len(errors) == 0

        assert typed.rows[0] == ["1", "init", "True"]
        assert typed.rows[1] == ["2", "kthread", "False"]

    def test_hex_conversion(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "mem.csv",
            "address,size\n0xFF,0x10\n0x1A,0x20\n",
        )
        spec_path = _write_spec(
            tmp / "mem.yaml", "mem.csv",
            {"address": "hex_int", "size": "hex_int"},
        )

        typed, errors = parse_table(csv_path, spec_path)

        assert len(errors) == 0
        assert typed.rows[0] == ["255", "16"]
        assert typed.rows[1] == ["26", "32"]


class TestParseTableBadData:
    """Conversion failures — the critical acceptance test."""

    def test_bad_integer_preserves_row(self, tmp: Path):
        """MF-040 DoD: A 'Bad Integer' results in a logged error
        but the row is preserved in the output."""
        csv_path = _write_csv(
            tmp / "proc.csv",
            "pid,name,ppid\n1,init,0\nBAD,chrome,1\n3,bash,1\n",
        )
        spec_path = _write_spec(
            tmp / "proc.yaml", "proc.csv",
            {"pid": "int", "name": "string", "ppid": "int"},
        )

        typed, errors = parse_table(csv_path, spec_path)

        # Row count invariant
        assert typed.row_count == 3
        assert typed.input_row_count == 3

        # Error captured
        assert len(errors) == 1
        assert errors[0].column == "pid"
        assert errors[0].raw_value == "BAD"
        assert errors[0].expected_type == "int"
        assert errors[0].row_index == 1

        # Rows intact
        assert typed.rows[0] == ["1", "init", "0"]
        assert typed.rows[1] == ["BAD", "chrome", "1"]  # raw preserved
        assert typed.rows[2] == ["3", "bash", "1"]

    def test_multiple_errors_in_one_row(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "multi.csv",
            "a,b,c\nX,Y,Z\n",
        )
        spec_path = _write_spec(
            tmp / "multi.yaml", "multi.csv",
            {"a": "int", "b": "int", "c": "int"},
        )

        typed, errors = parse_table(csv_path, spec_path)

        assert typed.row_count == 1
        assert len(errors) == 3

    def test_empty_cells_no_error(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "sparse.csv",
            "pid,name\n,init\n2,\n",
        )
        spec_path = _write_spec(
            tmp / "sparse.yaml", "sparse.csv",
            {"pid": "int", "name": "string"},
        )

        typed, errors = parse_table(csv_path, spec_path)

        assert typed.row_count == 2
        assert len(errors) == 0
        # Empty cells kept as-is (no error on empty)
        assert typed.rows[0][0] == ""
        assert typed.rows[1][1] == ""


class TestParseTableRowCountInvariant:
    """Output row count MUST equal input row count."""

    def test_invariant_clean(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "ok.csv",
            "x\n1\n2\n3\n4\n5\n",
        )
        spec_path = _write_spec(tmp / "ok.yaml", "ok.csv", {"x": "int"})

        typed, _ = parse_table(csv_path, spec_path)
        assert typed.row_count == 5

    def test_invariant_with_errors(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "mixed.csv",
            "x\n1\nBAD\n3\nNOPE\n5\n",
        )
        spec_path = _write_spec(tmp / "mixed.yaml", "mixed.csv", {"x": "int"})

        typed, errors = parse_table(csv_path, spec_path)
        assert typed.row_count == 5
        assert typed.input_row_count == 5
        assert len(errors) == 2

    def test_invariant_all_bad(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "allbad.csv",
            "x\nA\nB\nC\n",
        )
        spec_path = _write_spec(tmp / "allbad.yaml", "allbad.csv", {"x": "int"})

        typed, errors = parse_table(csv_path, spec_path)
        assert typed.row_count == 3
        assert typed.input_row_count == 3
        assert len(errors) == 3


class TestParseTableColumnsNotInSpec:
    """Columns not declared in the spec pass through unchanged."""

    def test_extra_csv_columns(self, tmp: Path):
        csv_path = _write_csv(
            tmp / "extra.csv",
            "pid,name,secret\n1,init,hidden\n",
        )
        # Spec only covers pid, not name or secret
        spec_path = _write_spec(
            tmp / "extra.yaml", "extra.csv", {"pid": "int"},
        )

        typed, errors = parse_table(csv_path, spec_path)

        assert len(errors) == 0
        assert typed.rows[0] == ["1", "init", "hidden"]


# ═══════════════════════════════════════════════════════════════════════════
# 4. TypedTable.to_raw_table
# ═══════════════════════════════════════════════════════════════════════════


class TestTypedTableToRawTable:
    """Conversion back to RawTable for write_csv_safe compatibility."""

    def test_round_trip_headers(self, tmp: Path):
        csv_path = _write_csv(tmp / "rt.csv", "a,b\n1,2\n")
        spec_path = _write_spec(tmp / "rt.yaml", "rt.csv", {"a": "int", "b": "int"})

        typed, _ = parse_table(csv_path, spec_path)
        raw = typed.to_raw_table()

        assert raw.headers == ["a", "b"]
        assert raw.rows == [["1", "2"]]


# ═══════════════════════════════════════════════════════════════════════════
# 5. find_spec_for_csv
# ═══════════════════════════════════════════════════════════════════════════


class TestFindSpecForCsv:
    """Auto-discovery of spec files."""

    def test_found(self, tmp: Path):
        specs_dir = tmp / "specs"
        _write_spec(specs_dir / "process.yaml", "process.csv", {"pid": "int"})

        result = find_spec_for_csv(Path("whatever/process.csv"), specs_dir)
        assert result is not None
        assert result.name == "process.yaml"

    def test_not_found(self, tmp: Path):
        specs_dir = tmp / "specs"
        specs_dir.mkdir(parents=True)

        result = find_spec_for_csv(Path("missing/table.csv"), specs_dir)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# 6. write_parsing_errors
# ═══════════════════════════════════════════════════════════════════════════


class TestWriteParsingErrors:
    """Error CSV output in append mode."""

    def test_no_errors_returns_none(self, tmp: Path):
        result = write_parsing_errors([], tmp / "errors.csv", "test.csv")
        assert result is None

    def test_creates_file_with_header(self, tmp: Path):
        from memflow_parser.engine import ParseError

        errors = [
            ParseError(0, "pid", "BAD", "int", "invalid literal"),
        ]
        path = tmp / "errors.csv"
        write_parsing_errors(errors, path, "proc.csv")

        content = path.read_text(encoding="utf-8")
        assert "source_file" in content
        assert "proc.csv" in content
        assert "BAD" in content

    def test_append_mode(self, tmp: Path):
        from memflow_parser.engine import ParseError

        path = tmp / "errors.csv"
        errors1 = [ParseError(0, "a", "X", "int", "err1")]
        errors2 = [ParseError(1, "b", "Y", "int", "err2")]

        write_parsing_errors(errors1, path, "file1.csv")
        write_parsing_errors(errors2, path, "file2.csv")

        content = path.read_text(encoding="utf-8")
        # Header only once
        assert content.count("source_file") == 1
        # Both errors present
        assert "file1.csv" in content
        assert "file2.csv" in content


# ═══════════════════════════════════════════════════════════════════════════
# 7. CLI integration — tools.memflow_parse_generic
# ═══════════════════════════════════════════════════════════════════════════


class TestCli:
    """End-to-end CLI tests for memflow_parse_generic."""

    def test_single_file_success(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"
        _write_csv(csv_dir / "process.csv", "pid,name\n1,init\n2,kthread\n")

        specs_dir = tmp / "specs"
        _write_spec(specs_dir / "process.yaml", "process.csv", {
            "pid": "int", "name": "string",
        })

        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "process.csv"),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        typed_csv = csv_dir / "typed_process.csv"
        assert typed_csv.exists()

        content = typed_csv.read_text(encoding="utf-8")
        assert "pid" in content
        assert "init" in content

    def test_bad_data_returns_exit_1(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"
        _write_csv(csv_dir / "proc.csv", "pid,name\nBAD,init\n")

        specs_dir = tmp / "specs"
        _write_spec(specs_dir / "proc.yaml", "proc.csv", {"pid": "int", "name": "string"})

        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "proc.csv"),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 1
        assert (csv_dir / "typed_proc.csv").exists()
        assert (csv_dir / "_parsing_errors.csv").exists()

    def test_missing_spec_returns_exit_2(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"
        _write_csv(csv_dir / "orphan.csv", "x\n1\n")

        specs_dir = tmp / "specs"
        specs_dir.mkdir(parents=True)

        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "orphan.csv"),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 2

    def test_missing_input_returns_exit_2(self, tmp: Path):
        case = tmp / "case"
        case.mkdir(parents=True)
        specs_dir = tmp / "specs"
        specs_dir.mkdir(parents=True)

        code = main([
            "--case", str(case),
            "--in", str(tmp / "nonexistent.csv"),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 2

    def test_directory_mode(self, tmp: Path):
        """Passing a directory as --in parses all CSVs inside."""
        case = tmp / "case"
        csv_dir = case / "csv"
        _write_csv(csv_dir / "alpha.csv", "a\n1\n2\n")
        _write_csv(csv_dir / "beta.csv", "b\n3\n4\n")

        specs_dir = tmp / "specs"
        _write_spec(specs_dir / "alpha.yaml", "alpha.csv", {"a": "int"})
        _write_spec(specs_dir / "beta.yaml", "beta.csv", {"b": "int"})

        code = main([
            "--case", str(case),
            "--in", str(csv_dir),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        assert (csv_dir / "typed_alpha.csv").exists()
        assert (csv_dir / "typed_beta.csv").exists()


# ═══════════════════════════════════════════════════════════════════════════
# 8. End-to-end: full pipeline
# ═══════════════════════════════════════════════════════════════════════════


class TestEndToEnd:
    """Full pipeline: raw CSV → spec → parse → typed CSV."""

    def test_process_table_pipeline(self, tmp: Path):
        """Simulate: ``python tools/memflow_parse_generic.py --case ./case1``
        producing ``typed_process.csv``."""
        case = tmp / "case1"
        csv_dir = case / "csv"

        # -- Raw CSV -------------------------------------------------------- #
        _write_csv(csv_dir / "process.csv", (
            "pid,name,ppid,address\n"
            "1,init,0,0xFF\n"
            "2,kthread,0,0x1A\n"
            "INVALID,chrome,1,0xBEEF\n"
        ))

        # -- Spec (user-edited from scaffold) ------------------------------- #
        specs_dir = tmp / "specs"
        _write_spec(specs_dir / "process.yaml", "process.csv", {
            "pid": "int",
            "name": "string",
            "ppid": "int",
            "address": "hex_int",
        })

        # -- Run parser ----------------------------------------------------- #
        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "process.csv"),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 1  # one parse error expected

        # -- Verify typed CSV ----------------------------------------------- #
        typed_csv = csv_dir / "typed_process.csv"
        assert typed_csv.exists()

        lines = typed_csv.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 4  # header + 3 data rows (none dropped!)

        # -- Verify error log ----------------------------------------------- #
        error_csv = csv_dir / "_parsing_errors.csv"
        assert error_csv.exists()
        error_content = error_csv.read_text(encoding="utf-8")
        assert "INVALID" in error_content
        assert "pid" in error_content

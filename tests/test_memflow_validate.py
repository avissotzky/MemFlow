"""
tests.test_memflow_validate
============================
Unit tests for :mod:`tools.memflow_validate` (MF-070).

Covers:
- Manifest loading.
- Parity check (pass and fail).
- Constraint check (non-null typed columns).
- Relational check (PID cross-reference).
- Markdown report generation.
- CLI main() with exit codes.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from memflow_common.csv_io import RawTable, write_csv_safe
from tools.memflow_validate import (
    CheckResult,
    ValidationReport,
    check_constraints,
    check_parity,
    check_relations,
    load_manifest,
    main,
    write_validation_report,
)


# ── Fixtures ──────────────────────────────────────────────────────────── #


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Shorthand for the pytest-provided temporary directory."""
    return tmp_path


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> Path:
    """Helper: write a CSV file using the MemFlow writer."""
    table = RawTable(headers=headers, rows=rows)
    write_csv_safe(table, path)
    return path


def _write_text(path: Path, content: str) -> Path:
    """Helper: write a text file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ── 1. Manifest loading ──────────────────────────────────────────────── #


class TestLoadManifest:

    def test_load_valid_manifest(self, tmp: Path):
        _write_csv(
            tmp / "manifest.csv",
            ["filename", "row_count", "sha256", "header_count", "anomalies"],
            [
                ["process.csv", "42", "abc123", "5", ""],
                ["net.csv", "10", "def456", "3", ""],
            ],
        )
        manifest = load_manifest(tmp / "manifest.csv")

        assert "process.csv" in manifest
        assert manifest["process.csv"]["row_count"] == 42
        assert manifest["net.csv"]["row_count"] == 10

    def test_missing_column_returns_empty(self, tmp: Path):
        _write_csv(
            tmp / "bad.csv",
            ["name", "count"],  # wrong column names
            [["a", "1"]],
        )
        manifest = load_manifest(tmp / "bad.csv")
        assert manifest == {}


# ── 2. Parity check ──────────────────────────────────────────────────── #


class TestCheckParity:

    def test_parity_pass(self, tmp: Path):
        # Manifest says process.csv has 3 rows
        manifest = {"process.csv": {"row_count": 3, "sha256": "x", "header_count": 2}}

        # typed_process.csv also has 3 rows
        csv_dir = tmp / "csv"
        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "a"], ["2", "b"], ["3", "c"],
        ])

        results = check_parity(manifest, csv_dir)
        assert len(results) == 1
        assert results[0].status == "PASS"
        assert results[0].check == "parity"

    def test_parity_fail_row_mismatch(self, tmp: Path):
        manifest = {"process.csv": {"row_count": 5, "sha256": "x", "header_count": 2}}

        csv_dir = tmp / "csv"
        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "a"], ["2", "b"],
        ])

        results = check_parity(manifest, csv_dir)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert "ROW MISMATCH" in results[0].detail

    def test_parity_fail_missing_manifest_entry(self, tmp: Path):
        manifest = {}  # No entries

        csv_dir = tmp / "csv"
        _write_csv(csv_dir / "typed_unknown.csv", ["a"], [["1"]])

        results = check_parity(manifest, csv_dir)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert "No manifest entry" in results[0].detail

    def test_parity_no_typed_files(self, tmp: Path):
        manifest = {"process.csv": {"row_count": 5, "sha256": "x", "header_count": 2}}
        csv_dir = tmp / "csv"
        csv_dir.mkdir(parents=True)

        results = check_parity(manifest, csv_dir)
        assert results == []


# ── 3. Constraint check ──────────────────────────────────────────────── #


class TestCheckConstraints:

    def test_constraint_pass(self, tmp: Path):
        csv_dir = tmp / "csv"
        specs_dir = tmp / "specs"

        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "svchost.exe"],
            ["2", "explorer.exe"],
        ])

        _write_text(specs_dir / "process.yaml", textwrap.dedent("""\
            table: process.csv
            columns:
              pid: { type: "int" }
              name: { type: "string" }
            validations: []
        """))

        results = check_constraints(csv_dir, specs_dir)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_constraint_fail_null_typed_column(self, tmp: Path):
        csv_dir = tmp / "csv"
        specs_dir = tmp / "specs"

        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "svchost.exe"],
            ["", "explorer.exe"],   # pid is empty — typed int column
            ["3", "lsass.exe"],
        ])

        _write_text(specs_dir / "process.yaml", textwrap.dedent("""\
            table: process.csv
            columns:
              pid: { type: "int" }
              name: { type: "string" }
            validations: []
        """))

        results = check_constraints(csv_dir, specs_dir)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert "pid" in results[0].detail

    def test_constraint_skipped_no_spec(self, tmp: Path):
        csv_dir = tmp / "csv"
        specs_dir = tmp / "specs"
        specs_dir.mkdir(parents=True)

        _write_csv(csv_dir / "typed_orphan.csv", ["a"], [["1"]])

        results = check_constraints(csv_dir, specs_dir)
        assert results == []  # Skipped, no spec found

    def test_constraint_pass_only_raw_string_columns(self, tmp: Path):
        csv_dir = tmp / "csv"
        specs_dir = tmp / "specs"

        _write_csv(csv_dir / "typed_notes.csv", ["text", "author"], [
            ["hello", "alice"],
        ])

        _write_text(specs_dir / "notes.yaml", textwrap.dedent("""\
            table: notes.csv
            columns:
              text: { type: "raw" }
              author: { type: "string" }
            validations: []
        """))

        results = check_constraints(csv_dir, specs_dir)
        assert len(results) == 1
        assert results[0].status == "PASS"
        assert "No typed" in results[0].detail


# ── 4. Relational check ──────────────────────────────────────────────── #


class TestCheckRelations:

    def test_relation_pass(self, tmp: Path):
        csv_dir = tmp / "csv"
        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "a"], ["2", "b"], ["3", "c"],
        ])
        _write_csv(csv_dir / "typed_net.csv", ["pid", "port"], [
            ["1", "80"], ["2", "443"],
        ])

        results = check_relations(csv_dir)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_relation_fail_orphan_pid(self, tmp: Path):
        csv_dir = tmp / "csv"
        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "a"],
        ])
        _write_csv(csv_dir / "typed_net.csv", ["pid", "port"], [
            ["1", "80"], ["999", "443"],  # 999 not in process
        ])

        results = check_relations(csv_dir)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert "999" in results[0].detail

    def test_relation_skipped_missing_tables(self, tmp: Path):
        csv_dir = tmp / "csv"
        csv_dir.mkdir(parents=True)
        # No typed_process.csv or typed_net.csv

        results = check_relations(csv_dir)
        assert results == []

    def test_relation_skipped_no_pid_column(self, tmp: Path):
        csv_dir = tmp / "csv"
        _write_csv(csv_dir / "typed_process.csv", ["id", "name"], [
            ["1", "a"],
        ])
        _write_csv(csv_dir / "typed_net.csv", ["pid", "port"], [
            ["1", "80"],
        ])

        # typed_process.csv has "id" not "pid" → skip
        results = check_relations(csv_dir)
        assert results == []


# ── 5. Report writer ─────────────────────────────────────────────────── #


class TestWriteReport:

    def test_report_markdown_created(self, tmp: Path):
        report = ValidationReport(
            generated_at="2025-01-01T00:00:00+00:00",
            case_directory="/cases/test",
            results=[
                CheckResult("process.csv", "parity", "PASS", "raw=10, typed=10"),
                CheckResult("net.csv", "parity", "FAIL", "ROW MISMATCH — raw=5, typed=3"),
            ],
        )

        path = write_validation_report(report, tmp / "report.md")
        assert path.exists()

        content = path.read_text(encoding="utf-8")
        assert "# MemFlow Validation Report" in content
        assert "PASS" in content
        assert "**FAIL**" in content
        assert "process.csv" in content
        assert "net.csv" in content

    def test_report_has_failures(self):
        report = ValidationReport(results=[
            CheckResult("x", "parity", "FAIL", ""),
        ])
        assert report.has_failures is True
        assert report.fail_count == 1

    def test_report_all_pass(self):
        report = ValidationReport(results=[
            CheckResult("x", "parity", "PASS", ""),
            CheckResult("y", "constraint", "PASS", ""),
        ])
        assert report.has_failures is False
        assert report.pass_count == 2


# ── 6. CLI main() ────────────────────────────────────────────────────── #


class TestMain:

    def test_main_all_pass(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"
        artifacts = case / "artifacts"
        specs_dir = tmp / "specs"

        # Manifest
        _write_csv(
            artifacts / "_inventory_manifest.csv",
            ["filename", "row_count", "sha256", "header_count", "anomalies"],
            [["process.csv", "2", "abc", "2", ""]],
        )

        # Typed CSV with matching row count
        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "a"], ["2", "b"],
        ])

        # Spec
        _write_text(specs_dir / "process.yaml", textwrap.dedent("""\
            table: process.csv
            columns:
              pid: { type: "int" }
              name: { type: "string" }
            validations: []
        """))

        code = main([
            "--case", str(case),
            "--in", str(csv_dir),
            "--specs", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        assert (artifacts / "validation_report.md").exists()

    def test_main_parity_fail(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"
        artifacts = case / "artifacts"

        _write_csv(
            artifacts / "_inventory_manifest.csv",
            ["filename", "row_count", "sha256", "header_count", "anomalies"],
            [["process.csv", "10", "abc", "2", ""]],
        )

        _write_csv(csv_dir / "typed_process.csv", ["pid", "name"], [
            ["1", "a"],
        ])

        code = main([
            "--case", str(case),
            "--in", str(csv_dir),
            "--log-level", "ERROR",
        ])

        assert code == 1  # FAIL

    def test_main_missing_manifest(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"
        csv_dir.mkdir(parents=True)

        code = main([
            "--case", str(case),
            "--in", str(csv_dir),
            "--log-level", "ERROR",
        ])

        assert code == 2  # Fatal — no manifest

    def test_main_missing_typed_dir(self, tmp: Path):
        case = tmp / "case"
        case.mkdir(parents=True)

        code = main([
            "--case", str(case),
            "--in", str(case / "nonexistent"),
            "--log-level", "ERROR",
        ])

        assert code == 2  # Fatal — dir doesn't exist

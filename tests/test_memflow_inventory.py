"""
tests.test_memflow_inventory
============================
Unit tests for :mod:`tools.memflow_inventory`.

Covers:
- Scanning a directory of CSV files.
- Detecting anomalies: duplicate headers, empty files, locked files.
- JSON inventory output format and content.
- CSV manifest output.
- CLI argument parsing and exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from tools.memflow_inventory import (
    build_inventory,
    detect_anomalies,
    main,
    scan_csv_directory,
    write_inventory_json,
    write_inventory_manifest,
)
from memflow_common.csv_io import RawTable, read_csv_safe


# ── Helpers ────────────────────────────────────────────────────────────── #


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Shorthand for pytest-provided temp directory."""
    return tmp_path


def _make_csv(directory: Path, name: str, content: str) -> Path:
    """Write a UTF-8 CSV file under *directory*."""
    p = directory / name
    p.write_text(content, encoding="utf-8")
    return p


def _make_case(tmp: Path, csvs: Dict[str, str]) -> Path:
    """Create a minimal case directory with CSVs in ``csv/``."""
    csv_dir = tmp / "case" / "csv"
    csv_dir.mkdir(parents=True)
    for name, content in csvs.items():
        _make_csv(csv_dir, name, content)
    return tmp / "case"


# ── 1. Anomaly detection ──────────────────────────────────────────────── #


class TestDetectAnomalies:
    """Unit tests for the anomaly detection function."""

    def test_no_anomalies_on_good_table(self, tmp: Path):
        table = RawTable(headers=["A", "B"], rows=[["1", "2"]])
        result = detect_anomalies(tmp / "good.csv", table, None)
        assert result == []

    def test_empty_file_detected(self, tmp: Path):
        table = RawTable(headers=[], rows=[])
        result = detect_anomalies(tmp / "empty.csv", table, None)
        assert "empty_file" in result

    def test_empty_data_detected(self, tmp: Path):
        table = RawTable(headers=["A", "B"], rows=[])
        result = detect_anomalies(tmp / "header_only.csv", table, None)
        assert "empty_data" in result

    def test_duplicate_headers_detected(self, tmp: Path):
        table = RawTable(headers=["pid", "name", "pid"], rows=[["1", "a", "2"]])
        result = detect_anomalies(tmp / "dup.csv", table, None)
        assert "duplicate_header: pid" in result

    def test_multiple_duplicate_headers(self, tmp: Path):
        table = RawTable(
            headers=["A", "B", "A", "C", "B"],
            rows=[["1", "2", "3", "4", "5"]],
        )
        result = detect_anomalies(tmp / "multi_dup.csv", table, None)
        assert "duplicate_header: A" in result
        assert "duplicate_header: B" in result

    def test_read_error_reported(self, tmp: Path):
        result = detect_anomalies(tmp / "broken.csv", None, "locked_by_os")
        assert "read_error: locked_by_os" in result

    def test_error_short_circuits(self, tmp: Path):
        """When there's a read error, no further anomaly checks run."""
        result = detect_anomalies(tmp / "broken.csv", None, "some error")
        assert len(result) == 1
        assert result[0].startswith("read_error")


# ── 2. Directory scanning ─────────────────────────────────────────────── #


class TestScanCsvDirectory:
    """Scanning a directory for CSV files."""

    def test_finds_all_csvs(self, tmp: Path):
        csv_dir = tmp / "csvs"
        csv_dir.mkdir()
        _make_csv(csv_dir, "alpha.csv", "A,B\n1,2\n")
        _make_csv(csv_dir, "beta.csv", "X\n10\n20\n")
        # Non-CSV file should be ignored.
        (csv_dir / "notes.txt").write_text("not a csv")

        entries = scan_csv_directory(csv_dir)
        names = [e["filename"] for e in entries]

        assert len(entries) == 2
        assert "alpha.csv" in names
        assert "beta.csv" in names

    def test_correct_metadata(self, tmp: Path):
        csv_dir = tmp / "csvs"
        csv_dir.mkdir()
        _make_csv(csv_dir, "data.csv", "Name,Age\nAlice,30\nBob,25\n")

        entries = scan_csv_directory(csv_dir)
        entry = entries[0]

        assert entry["filename"] == "data.csv"
        assert entry["headers"] == ["Name", "Age"]
        assert entry["row_count"] == 2
        assert len(entry["sha256"]) == 64  # SHA-256 hex digest
        assert entry["anomalies"] == []

    def test_empty_file_flagged(self, tmp: Path):
        csv_dir = tmp / "csvs"
        csv_dir.mkdir()
        _make_csv(csv_dir, "empty.csv", "")

        entries = scan_csv_directory(csv_dir)
        assert "empty_file" in entries[0]["anomalies"]

    def test_duplicate_headers_flagged(self, tmp: Path):
        csv_dir = tmp / "csvs"
        csv_dir.mkdir()
        _make_csv(csv_dir, "dup.csv", "id,name,id\n1,a,2\n")

        entries = scan_csv_directory(csv_dir)
        assert any("duplicate_header" in a for a in entries[0]["anomalies"])

    def test_nonexistent_directory(self, tmp: Path):
        entries = scan_csv_directory(tmp / "does_not_exist")
        assert entries == []

    def test_locked_file_handled(self, tmp: Path):
        """Simulate an OS-locked file via mocking."""
        csv_dir = tmp / "csvs"
        csv_dir.mkdir()
        _make_csv(csv_dir, "locked.csv", "A\n1\n")

        with patch(
            "tools.memflow_inventory.read_csv_safe",
            side_effect=PermissionError("file is locked"),
        ):
            entries = scan_csv_directory(csv_dir)

        assert entries[0]["row_count"] == 0
        assert any("locked_by_os" in a for a in entries[0]["anomalies"])


# ── 3. Full inventory build ───────────────────────────────────────────── #


class TestBuildInventory:
    """End-to-end inventory generation."""

    def test_inventory_structure(self, tmp: Path):
        case = _make_case(tmp, {
            "process.csv": "pid,name\n1,svchost\n2,explorer\n",
            "network.csv": "src,dst,port\n10.0.0.1,10.0.0.2,443\n",
        })

        inv = build_inventory(case, case / "csv")

        assert inv["total_files"] == 2
        assert len(inv["files"]) == 2
        assert "anomalies_summary" in inv
        assert "generated_at" in inv

    def test_anomalies_summary_aggregation(self, tmp: Path):
        case = _make_case(tmp, {
            "good.csv": "A,B\n1,2\n",
            "empty.csv": "",
            "dup.csv": "X,Y,X\n1,2,3\n",
        })

        inv = build_inventory(case, case / "csv")
        summary = inv["anomalies_summary"]

        assert "empty.csv" in summary["empty_files"]
        assert "dup.csv" in summary["duplicate_headers"]
        assert summary["locked_files"] == []


# ── 4. JSON output ────────────────────────────────────────────────────── #


class TestWriteInventoryJson:
    """JSON file writing."""

    def test_creates_valid_json(self, tmp: Path):
        case = _make_case(tmp, {"data.csv": "Col\n1\n"})
        inv = build_inventory(case, case / "csv")

        out = tmp / "output" / "inventory.json"
        write_inventory_json(inv, out)

        assert out.exists()
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["total_files"] == 1
        assert loaded["files"][0]["filename"] == "data.csv"

    def test_creates_parent_dirs(self, tmp: Path):
        inv = {"files": [], "total_files": 0, "anomalies_summary": {}}
        out = tmp / "deep" / "nested" / "inv.json"
        write_inventory_json(inv, out)
        assert out.exists()


# ── 5. CSV manifest output ────────────────────────────────────────────── #


class TestWriteInventoryManifest:
    """CSV manifest writing."""

    def test_manifest_round_trips(self, tmp: Path):
        case = _make_case(tmp, {
            "a.csv": "H1,H2\n1,2\n3,4\n",
            "b.csv": "X\n10\n",
        })
        inv = build_inventory(case, case / "csv")

        manifest = tmp / "manifest.csv"
        write_inventory_manifest(inv, manifest)

        assert manifest.exists()
        table = read_csv_safe(manifest)
        assert table.headers == [
            "filename", "row_count", "sha256", "header_count", "anomalies",
        ]
        assert table.row_count == 2

    def test_manifest_anomaly_column(self, tmp: Path):
        case = _make_case(tmp, {"dup.csv": "A,B,A\n1,2,3\n"})
        inv = build_inventory(case, case / "csv")

        manifest = tmp / "manifest.csv"
        write_inventory_manifest(inv, manifest)

        table = read_csv_safe(manifest)
        anomaly_cell = table.rows[0][4]  # "anomalies" column
        assert "duplicate_header" in anomaly_cell


# ── 6. CLI integration ────────────────────────────────────────────────── #


class TestCli:
    """Test the main() entry point."""

    def test_success_exit_code(self, tmp: Path):
        case = _make_case(tmp, {"ok.csv": "A\n1\n2\n"})
        code = main(["--case", str(case), "--log-level", "ERROR"])
        assert code == 0

    def test_anomalies_return_exit_1(self, tmp: Path):
        case = _make_case(tmp, {"empty.csv": ""})
        code = main(["--case", str(case), "--log-level", "ERROR"])
        assert code == 1

    def test_missing_input_dir_returns_exit_2(self, tmp: Path):
        case = tmp / "no_such_case"
        case.mkdir()
        # csv/ sub-directory does NOT exist
        code = main(["--case", str(case), "--log-level", "ERROR"])
        assert code == 2

    def test_outputs_created(self, tmp: Path):
        case = _make_case(tmp, {"proc.csv": "pid,name\n1,init\n"})
        main(["--case", str(case), "--log-level", "ERROR"])

        assert (case / "docs" / "03_csv_inventory.json").exists()
        assert (case / "artifacts" / "_inventory_manifest.csv").exists()

    def test_custom_out_dir(self, tmp: Path):
        case = _make_case(tmp, {"x.csv": "Col\n1\n"})
        out = tmp / "custom_out"
        main(["--case", str(case), "--out", str(out), "--log-level", "ERROR"])

        assert (out / "docs" / "03_csv_inventory.json").exists()
        assert (out / "artifacts" / "_inventory_manifest.csv").exists()

    def test_custom_in_dir(self, tmp: Path):
        # Put CSVs in a non-standard location.
        alt_dir = tmp / "alt_csvs"
        alt_dir.mkdir()
        _make_csv(alt_dir, "special.csv", "H\nval\n")

        case = tmp / "mycase"
        case.mkdir()

        code = main([
            "--case", str(case),
            "--in", str(alt_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        inv = json.loads(
            (case / "docs" / "03_csv_inventory.json").read_text(encoding="utf-8")
        )
        assert inv["files"][0]["filename"] == "special.csv"

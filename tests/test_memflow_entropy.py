"""
tests.test_memflow_entropy
===========================
Unit tests for :mod:`tools.memflow_entropy` (MF-080).

Covers:
- Shannon entropy calculation.
- MD5/SHA256 hash computation.
- File-path resolution strategies.
- Enrichment pipeline (found, not_found, read_error).
- CLI main() with exit codes.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path

import pytest

from memflow_common.csv_io import RawTable, read_csv_safe, write_csv_safe
from tools.memflow_entropy import (
    compute_hashes,
    enrich_files,
    main,
    shannon_entropy,
)


# ── Fixtures ──────────────────────────────────────────────────────────── #


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Shorthand for the pytest-provided temporary directory."""
    return tmp_path


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> Path:
    table = RawTable(headers=headers, rows=rows)
    write_csv_safe(table, path)
    return path


def _write_bin(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ── 1. Shannon entropy ───────────────────────────────────────────────── #


class TestShannonEntropy:

    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        # All same bytes → entropy = 0.0
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_two_bytes_equal_frequency(self):
        # Two symbols, equal frequency → entropy = 1.0
        data = b"\x00\x01" * 500
        assert abs(shannon_entropy(data) - 1.0) < 0.001

    def test_all_256_bytes_equal(self):
        # Maximum entropy = 8.0 (log2(256))
        data = bytes(range(256)) * 100
        entropy = shannon_entropy(data)
        assert abs(entropy - 8.0) < 0.001

    def test_entropy_range(self):
        # Any data should produce 0.0 <= entropy <= 8.0
        data = b"Hello, World! This is a test."
        entropy = shannon_entropy(data)
        assert 0.0 <= entropy <= 8.0

    def test_high_entropy_random_like(self):
        # Pseudorandom-ish data should have high entropy
        import os
        data = os.urandom(10000)
        entropy = shannon_entropy(data)
        assert entropy > 7.0  # Truly random ≈ 8.0


# ── 2. Hash computation ──────────────────────────────────────────────── #


class TestComputeHashes:

    def test_known_hashes(self):
        data = b"hello world"
        md5, sha256 = compute_hashes(data)
        assert md5 == hashlib.md5(data).hexdigest()
        assert sha256 == hashlib.sha256(data).hexdigest()

    def test_empty_input(self):
        md5, sha256 = compute_hashes(b"")
        assert md5 == hashlib.md5(b"").hexdigest()
        assert sha256 == hashlib.sha256(b"").hexdigest()


# ── 3. File enrichment pipeline ──────────────────────────────────────── #


class TestEnrichFiles:

    def test_basic_enrichment(self, tmp: Path):
        forensic = tmp / "forensic_files"
        _write_bin(forensic / "malware.exe", b"\x00" * 100)
        _write_bin(forensic / "readme.txt", b"Hello World")

        _write_csv(tmp / "files.csv", ["file_path", "file_id"], [
            ["malware.exe", "1"],
            ["readme.txt", "2"],
        ])

        output = enrich_files(tmp / "files.csv", forensic)

        assert output.row_count == 2
        # Both files found
        assert output.rows[0][-1] == "ok"  # status
        assert output.rows[1][-1] == "ok"

        # malware.exe is all zeros → entropy = 0
        assert output.rows[0][2] == "0.000000"  # entropy

        # Both have MD5 and SHA256
        assert len(output.rows[0][3]) == 32  # MD5 hex
        assert len(output.rows[0][4]) == 64  # SHA256 hex

    def test_file_not_found(self, tmp: Path):
        forensic = tmp / "forensic_files"
        forensic.mkdir()

        _write_csv(tmp / "files.csv", ["file_path"], [
            ["nonexistent.dll"],
        ])

        output = enrich_files(tmp / "files.csv", forensic)
        assert output.row_count == 1
        assert output.rows[0][-1] == "not_found"

    def test_mixed_found_and_missing(self, tmp: Path):
        forensic = tmp / "forensic_files"
        _write_bin(forensic / "exists.txt", b"data")

        _write_csv(tmp / "files.csv", ["path"], [
            ["exists.txt"],
            ["missing.txt"],
        ])

        output = enrich_files(tmp / "files.csv", forensic)
        assert output.row_count == 2
        assert output.rows[0][-1] == "ok"
        assert output.rows[1][-1] == "not_found"

    def test_column_name_detection(self, tmp: Path):
        forensic = tmp / "forensic_files"
        _write_bin(forensic / "test.bin", b"\xff")

        # Using "filepath" instead of "file_path"
        _write_csv(tmp / "files.csv", ["filepath", "size"], [
            ["test.bin", "1"],
        ])

        output = enrich_files(tmp / "files.csv", forensic)
        assert output.rows[0][-1] == "ok"

    def test_absolute_path_resolution(self, tmp: Path):
        forensic = tmp / "forensic_files"
        target = _write_bin(forensic / "kernel32.dll", b"\x90" * 50)

        # Use absolute path
        _write_csv(tmp / "files.csv", ["file_path"], [
            [str(target)],
        ])

        output = enrich_files(tmp / "files.csv", forensic)
        assert output.rows[0][-1] == "ok"

    def test_nested_path_resolution(self, tmp: Path):
        forensic = tmp / "forensic_files"
        _write_bin(forensic / "Windows" / "System32" / "cmd.exe", b"\xcc" * 20)

        # CSV has path relative to forensic dir
        _write_csv(tmp / "files.csv", ["file_path"], [
            ["Windows/System32/cmd.exe"],
        ])

        output = enrich_files(tmp / "files.csv", forensic)
        assert output.rows[0][-1] == "ok"

    def test_file_size_reported(self, tmp: Path):
        forensic = tmp / "forensic_files"
        _write_bin(forensic / "sized.bin", b"A" * 1234)

        _write_csv(tmp / "files.csv", ["file_path"], [
            ["sized.bin"],
        ])

        output = enrich_files(tmp / "files.csv", forensic)
        assert output.rows[0][5] == "1234"  # file_size column


# ── 4. CLI main() ────────────────────────────────────────────────────── #


class TestMain:

    def test_main_all_found(self, tmp: Path):
        case = tmp / "case"
        forensic = case / "forensic_files"
        csv_dir = case / "csv"

        _write_bin(forensic / "a.txt", b"content-a")
        _write_bin(forensic / "b.txt", b"content-b")

        _write_csv(csv_dir / "files.csv", ["file_path"], [
            ["a.txt"], ["b.txt"],
        ])

        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "files.csv"),
            "--log-level", "ERROR",
        ])

        assert code == 0
        out = csv_dir / "file_entropy.csv"
        assert out.exists()

        result = read_csv_safe(out)
        assert result.row_count == 2

    def test_main_partial_not_found(self, tmp: Path):
        case = tmp / "case"
        forensic = case / "forensic_files"
        csv_dir = case / "csv"

        _write_bin(forensic / "found.txt", b"data")

        _write_csv(csv_dir / "files.csv", ["file_path"], [
            ["found.txt"], ["missing.txt"],
        ])

        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "files.csv"),
            "--log-level", "ERROR",
        ])

        assert code == 1  # Partial — some not found

    def test_main_missing_input(self, tmp: Path):
        case = tmp / "case"
        case.mkdir(parents=True)

        code = main([
            "--case", str(case),
            "--in", str(case / "nonexistent.csv"),
            "--log-level", "ERROR",
        ])

        assert code == 2  # Fatal

    def test_main_custom_output_dir(self, tmp: Path):
        case = tmp / "case"
        forensic = case / "forensic_files"
        custom_out = tmp / "custom_out"

        _write_bin(forensic / "file.bin", b"\xde\xad\xbe\xef")
        _write_csv(case / "files.csv", ["file_path"], [["file.bin"]])

        code = main([
            "--case", str(case),
            "--in", str(case / "files.csv"),
            "--out", str(custom_out),
            "--log-level", "ERROR",
        ])

        assert code == 0
        assert (custom_out / "file_entropy.csv").exists()

    def test_main_forensic_dir_missing_warns(self, tmp: Path):
        case = tmp / "case"
        csv_dir = case / "csv"

        _write_csv(csv_dir / "files.csv", ["file_path"], [["x.bin"]])

        # forensic_files/ does not exist — tool should still run
        code = main([
            "--case", str(case),
            "--in", str(csv_dir / "files.csv"),
            "--log-level", "ERROR",
        ])

        assert code == 1  # partial — file not found
        assert (csv_dir / "file_entropy.csv").exists()

"""
tests.test_memflow_spec_scaffold
=================================
Unit tests for :mod:`tools.memflow_spec_scaffold`.

Covers:
- YAML spec content generation.
- Skipping tables with no headers.
- Skipping existing specs (and overwrite mode).
- Table-name derivation from filenames.
- CLI integration and exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tools.memflow_spec_scaffold import (
    build_yaml_spec,
    generate_specs,
    main,
    table_name_from_filename,
)


# ── Helpers ────────────────────────────────────────────────────────────── #


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Shorthand for pytest-provided temp directory."""
    return tmp_path


def _write_inventory(path: Path, files: List[Dict[str, Any]]) -> Path:
    """Write a minimal inventory JSON."""
    inventory = {
        "generated_at": "2026-02-12T00:00:00+00:00",
        "case_directory": str(path.parent),
        "scan_directory": str(path.parent / "csv"),
        "total_files": len(files),
        "files": files,
        "anomalies_summary": {},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    return path


def _make_inventory_entry(
    filename: str,
    headers: List[str],
    row_count: int = 10,
) -> Dict[str, Any]:
    """Build a single inventory file entry."""
    return {
        "filename": filename,
        "filepath": f"/fake/path/{filename}",
        "headers": headers,
        "row_count": row_count,
        "sha256": "a" * 64,
        "ingest_errors": 0,
        "anomalies": [],
    }


# ── 1. Table name derivation ─────────────────────────────────────────── #


class TestTableNameFromFilename:
    """Deriving spec file stems from CSV filenames."""

    def test_simple(self):
        assert table_name_from_filename("process.csv") == "process"

    def test_underscores(self):
        assert table_name_from_filename("my_data.csv") == "my_data"

    def test_multiple_dots(self):
        assert table_name_from_filename("foo.bar.csv") == "foo.bar"


# ── 2. YAML spec content ─────────────────────────────────────────────── #


class TestBuildYamlSpec:
    """Generated YAML content must match the expected template."""

    def test_basic_template(self):
        yaml = build_yaml_spec("process.csv", ["pid", "name"])

        assert "table: process.csv" in yaml
        assert "columns:" in yaml
        assert '  pid: { type: "raw" }' in yaml
        assert '  name: { type: "raw" }' in yaml
        assert "validations: []" in yaml

    def test_empty_headers_handled(self):
        yaml = build_yaml_spec("empty.csv", [])
        assert "columns:" in yaml
        # Should contain an indication that no headers were found.
        assert "No headers detected" in yaml

    def test_special_chars_quoted(self):
        yaml = build_yaml_spec("weird.csv", ["normal", "has:colon", "has{brace}"])
        assert '  normal: { type: "raw" }' in yaml
        assert '  "has:colon": { type: "raw" }' in yaml
        assert '  "has{brace}": { type: "raw" }' in yaml

    def test_trailing_newline(self):
        yaml = build_yaml_spec("t.csv", ["A"])
        assert yaml.endswith("\n")


# ── 3. Spec generation logic ─────────────────────────────────────────── #


class TestGenerateSpecs:
    """Core spec generation from inventory data."""

    def test_creates_yaml_files(self, tmp: Path):
        inventory = {
            "files": [
                _make_inventory_entry("process.csv", ["pid", "name"]),
                _make_inventory_entry("network.csv", ["src", "dst", "port"]),
            ],
        }
        specs_dir = tmp / "specs"

        results = generate_specs(inventory, specs_dir)

        assert results["process"] == "created"
        assert results["network"] == "created"
        assert (specs_dir / "process.yaml").exists()
        assert (specs_dir / "network.yaml").exists()

    def test_yaml_content_correct(self, tmp: Path):
        inventory = {
            "files": [_make_inventory_entry("proc.csv", ["pid", "cmd"])],
        }
        specs_dir = tmp / "specs"
        generate_specs(inventory, specs_dir)

        content = (specs_dir / "proc.yaml").read_text(encoding="utf-8")
        assert "table: proc.csv" in content
        assert '  pid: { type: "raw" }' in content
        assert '  cmd: { type: "raw" }' in content
        assert "validations: []" in content

    def test_skips_existing_specs(self, tmp: Path):
        inventory = {
            "files": [_make_inventory_entry("alpha.csv", ["A"])],
        }
        specs_dir = tmp / "specs"
        specs_dir.mkdir(parents=True)
        # Pre-create the spec file with custom content.
        existing = specs_dir / "alpha.yaml"
        existing.write_text("custom: content\n", encoding="utf-8")

        results = generate_specs(inventory, specs_dir)
        assert results["alpha"] == "skipped"
        # Content must NOT have been overwritten.
        assert existing.read_text(encoding="utf-8") == "custom: content\n"

    def test_overwrite_mode(self, tmp: Path):
        inventory = {
            "files": [_make_inventory_entry("alpha.csv", ["A", "B"])],
        }
        specs_dir = tmp / "specs"
        specs_dir.mkdir(parents=True)
        existing = specs_dir / "alpha.yaml"
        existing.write_text("old content\n", encoding="utf-8")

        results = generate_specs(inventory, specs_dir, overwrite=True)
        assert results["alpha"] == "created"
        new_content = existing.read_text(encoding="utf-8")
        assert "table: alpha.csv" in new_content

    def test_skips_no_headers(self, tmp: Path):
        inventory = {
            "files": [_make_inventory_entry("empty.csv", [])],
        }
        specs_dir = tmp / "specs"
        results = generate_specs(inventory, specs_dir)
        assert results["empty"] == "skipped_no_headers"
        assert not (specs_dir / "empty.yaml").exists()

    def test_creates_specs_dir(self, tmp: Path):
        inventory = {
            "files": [_make_inventory_entry("x.csv", ["Col"])],
        }
        specs_dir = tmp / "new" / "deep" / "specs"
        generate_specs(inventory, specs_dir)
        assert specs_dir.is_dir()
        assert (specs_dir / "x.yaml").exists()


# ── 4. CLI integration ────────────────────────────────────────────────── #


class TestCli:
    """Test the main() entry point."""

    def test_success(self, tmp: Path):
        case = tmp / "case"
        inv_path = case / "docs" / "03_csv_inventory.json"
        _write_inventory(inv_path, [
            _make_inventory_entry("alpha.csv", ["A", "B"]),
        ])

        specs_dir = tmp / "specs"
        code = main([
            "--case", str(case),
            "--out", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        assert (specs_dir / "alpha.yaml").exists()

    def test_missing_inventory_returns_exit_2(self, tmp: Path):
        case = tmp / "case"
        case.mkdir(parents=True)
        code = main([
            "--case", str(case),
            "--out", str(tmp / "specs"),
            "--log-level", "ERROR",
        ])
        assert code == 2

    def test_custom_in_path(self, tmp: Path):
        case = tmp / "case"
        case.mkdir(parents=True)
        inv_path = tmp / "custom" / "my_inventory.json"
        _write_inventory(inv_path, [
            _make_inventory_entry("beta.csv", ["X", "Y"]),
        ])

        specs_dir = tmp / "specs"
        code = main([
            "--case", str(case),
            "--in", str(inv_path),
            "--out", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        assert (specs_dir / "beta.yaml").exists()

    def test_multiple_files_generated(self, tmp: Path):
        case = tmp / "case"
        inv_path = case / "docs" / "03_csv_inventory.json"
        _write_inventory(inv_path, [
            _make_inventory_entry("proc.csv", ["pid", "name"]),
            _make_inventory_entry("net.csv", ["src", "dst"]),
            _make_inventory_entry("reg.csv", ["key", "value", "type"]),
        ])

        specs_dir = tmp / "specs"
        code = main([
            "--case", str(case),
            "--out", str(specs_dir),
            "--log-level", "ERROR",
        ])

        assert code == 0
        assert (specs_dir / "proc.yaml").exists()
        assert (specs_dir / "net.yaml").exists()
        assert (specs_dir / "reg.yaml").exists()


# ── 5. End-to-end: inventory → scaffold ───────────────────────────────── #


class TestEndToEnd:
    """Verify the full pipeline: run inventory, then scaffold from its output."""

    def test_inventory_then_scaffold(self, tmp: Path):
        """Build a case with CSVs, run inventory, then scaffold specs."""
        from tools.memflow_inventory import main as inv_main

        # Set up case with CSVs
        case = tmp / "case"
        csv_dir = case / "csv"
        csv_dir.mkdir(parents=True)
        (csv_dir / "process.csv").write_text(
            "pid,name,ppid\n1,init,0\n2,kthread,0\n", encoding="utf-8",
        )
        (csv_dir / "network.csv").write_text(
            "src,dst,port\n10.0.0.1,10.0.0.2,443\n", encoding="utf-8",
        )

        # Run inventory
        inv_code = inv_main(["--case", str(case), "--log-level", "ERROR"])
        assert inv_code == 0

        # Verify inventory JSON was created
        inv_json = case / "docs" / "03_csv_inventory.json"
        assert inv_json.exists()

        # Run scaffold
        specs_dir = tmp / "specs"
        scaffold_code = main([
            "--case", str(case),
            "--out", str(specs_dir),
            "--log-level", "ERROR",
        ])
        assert scaffold_code == 0

        # Verify specs were created
        assert (specs_dir / "process.yaml").exists()
        assert (specs_dir / "network.yaml").exists()

        # Verify spec content
        proc_spec = (specs_dir / "process.yaml").read_text(encoding="utf-8")
        assert "table: process.csv" in proc_spec
        assert "pid" in proc_spec
        assert "name" in proc_spec
        assert "ppid" in proc_spec

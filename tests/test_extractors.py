"""Tests for the plugin-based extractor architecture.

Covers:
- BaseExtractor helpers (write_csv, read_vfs_file, copy_forensic_csv)
- Auto-discovery of extractor plugins
- Individual extractor behaviour with mocked VMM
- Orchestrator CLI (--list, --only, --exclude)
- ExtractResult dataclass
"""

from __future__ import annotations

import csv
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from extractors.base import BaseExtractor, ExtractResult


# ── Fixtures ─────────────────────────────────────────────────

class _ConcreteExtractor(BaseExtractor):
    """Minimal concrete subclass for testing base helpers."""
    name = "test_concrete"
    output_filename = "test_concrete.csv"
    source = "api"

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        self.write_csv(out_dir, self.output_filename, ["a", "b"], [["1", "2"]])
        return ExtractResult(ok=True, rows=1, files_written=[self.output_filename])


def _make_vmm_mock(
    forensic_csvs: Dict[str, bytes] | None = None,
    vfs_files: Dict[str, bytes] | None = None,
) -> MagicMock:
    """Build a mock VMM with VFS read/list/write capabilities."""
    vmm = MagicMock()

    _forensic = forensic_csvs or {}
    _vfs = vfs_files or {}

    def _vfs_list(path: str) -> Dict[str, Dict[str, Any]]:
        if path == "/forensic/csv/":
            return {name: {"size": len(data)} for name, data in _forensic.items()}
        return {}

    def _vfs_read(path: str, size: int = 0, offset: int = 0) -> bytes:
        for name, data in _forensic.items():
            if path == f"/forensic/csv/{name}":
                return data[offset: offset + size] if size else data
        for vfs_path, data in _vfs.items():
            if path == vfs_path:
                return data[offset: offset + size] if size else data
        return b""

    vmm.vfs.list.side_effect = _vfs_list
    vmm.vfs.read.side_effect = _vfs_read
    return vmm


# ── ExtractResult ────────────────────────────────────────────

class TestExtractResult:
    def test_defaults(self):
        r = ExtractResult()
        assert r.ok is True
        assert r.rows == 0
        assert r.files_written == []
        assert r.error is None

    def test_custom_values(self):
        r = ExtractResult(ok=False, rows=42, files_written=["a.csv"], error="boom")
        assert r.ok is False
        assert r.rows == 42
        assert r.error == "boom"

    def test_files_written_not_shared(self):
        r1 = ExtractResult()
        r2 = ExtractResult()
        r1.files_written.append("x")
        assert r2.files_written == []


# ── BaseExtractor.write_csv ─────────────────────────────────

class TestWriteCsv:
    def test_creates_file(self, tmp_path: Path):
        ext = _ConcreteExtractor()
        p = ext.write_csv(tmp_path, "out.csv", ["h1", "h2"], [["a", "b"]])
        assert p.exists()
        assert p.name == "out.csv"

    def test_content_correct(self, tmp_path: Path):
        ext = _ConcreteExtractor()
        ext.write_csv(tmp_path, "out.csv", ["x", "y"], [["1", "2"], ["3", "4"]])
        with (tmp_path / "out.csv").open(encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert rows[0] == ["x", "y"]
        assert rows[1] == ["1", "2"]
        assert rows[2] == ["3", "4"]

    def test_all_fields_quoted(self, tmp_path: Path):
        ext = _ConcreteExtractor()
        ext.write_csv(tmp_path, "out.csv", ["h"], [["val"]])
        raw = (tmp_path / "out.csv").read_text(encoding="utf-8")
        assert '"h"' in raw
        assert '"val"' in raw

    def test_empty_rows(self, tmp_path: Path):
        ext = _ConcreteExtractor()
        p = ext.write_csv(tmp_path, "out.csv", ["h1"], [])
        lines = p.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1  # header only


# ── BaseExtractor.read_vfs_text ─────────────────────────────

class TestReadVfsText:
    def test_decodes_utf8(self):
        vmm = _make_vmm_mock(vfs_files={"/test.txt": b"hello world"})
        text = BaseExtractor.read_vfs_text(vmm, "/test.txt")
        assert text == "hello world"

    def test_handles_bad_encoding(self):
        vmm = _make_vmm_mock(vfs_files={"/bad.txt": b"\xff\xfe"})
        text = BaseExtractor.read_vfs_text(vmm, "/bad.txt")
        assert isinstance(text, str)


# ── BaseExtractor.copy_forensic_csv ─────────────────────────

class TestCopyForensicCsv:
    def test_copies_file(self, tmp_path: Path):
        content = b'"h1","h2"\n"a","b"\n"c","d"\n'
        vmm = _make_vmm_mock(forensic_csvs={"test.csv": content})
        result = BaseExtractor.copy_forensic_csv(vmm, "test.csv", tmp_path)
        assert result.ok is True
        assert result.rows == 2
        assert (tmp_path / "test.csv").exists()
        assert (tmp_path / "test.csv").read_bytes() == content

    def test_missing_csv(self, tmp_path: Path):
        vmm = _make_vmm_mock(forensic_csvs={})
        result = BaseExtractor.copy_forensic_csv(vmm, "nope.csv", tmp_path)
        assert result.ok is False
        assert "not found" in result.error

    def test_files_written_populated(self, tmp_path: Path):
        content = b'"h"\n"v"\n'
        vmm = _make_vmm_mock(forensic_csvs={"x.csv": content})
        result = BaseExtractor.copy_forensic_csv(vmm, "x.csv", tmp_path)
        assert result.files_written == ["x.csv"]


# ── BaseExtractor.copy_forensic_csvs_matching ───────────────

class TestCopyForensicCsvsMatching:
    def test_copies_matching_prefix(self, tmp_path: Path):
        vmm = _make_vmm_mock(forensic_csvs={
            "timeline_all.csv": b'"h"\n"v"\n',
            "timeline_net.csv": b'"h"\n"v1"\n"v2"\n',
            "process.csv": b'"h"\n"x"\n',
        })
        result = BaseExtractor.copy_forensic_csvs_matching(vmm, "timeline_", tmp_path)
        assert result.ok is True
        assert set(result.files_written) == {"timeline_all.csv", "timeline_net.csv"}
        assert (tmp_path / "timeline_all.csv").exists()
        assert (tmp_path / "timeline_net.csv").exists()
        assert not (tmp_path / "process.csv").exists()

    def test_no_matches(self, tmp_path: Path):
        vmm = _make_vmm_mock(forensic_csvs={"process.csv": b'"h"\n"v"\n'})
        result = BaseExtractor.copy_forensic_csvs_matching(vmm, "timeline_", tmp_path)
        assert result.ok is False


# ── Auto-discovery ──────────────────────────────────────────

class TestDiscovery:
    def test_discovers_all_extractors(self):
        from extractors import discover_extractors
        registry = discover_extractors()
        assert len(registry) >= 14
        assert "processes" in registry
        assert "dlls" in registry
        assert "netstat" in registry
        assert "modules" in registry
        assert "timelines" in registry
        assert "registry" not in registry

    def test_all_have_name_and_source(self):
        from extractors import discover_extractors
        for name, cls in discover_extractors().items():
            assert cls.name == name
            assert cls.source in ("api", "vfs", "forensic_csv")
            assert cls.output_filename

    def test_list_extractor_names(self):
        from extractors import list_extractor_names
        names = list_extractor_names()
        assert isinstance(names, list)
        assert names == sorted(names)
        assert "processes" in names


# ── Individual extractor behaviour ──────────────────────────

class TestProcessesExtractor:
    def test_extracts_process_list(self, tmp_path: Path):
        from extractors.processes import ProcessesExtractor

        proc = SimpleNamespace(
            pid=1234, ppid=4, name="test.exe", fullpath=r"C:\test.exe",
            sid="S-1-5-18", username="SYSTEM", cmdline="test.exe --flag",
            state=3, time_create="2026-01-01T00:00:00", time_exit="",
            wow64=False,
        )
        vmm = MagicMock()
        vmm.process_list.return_value = [proc]

        ext = ProcessesExtractor()
        result = ext.extract(vmm, tmp_path)
        assert result.ok is True
        assert result.rows == 1
        assert (tmp_path / "process.csv").exists()

        with (tmp_path / "process.csv").open(encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert rows[0] == [
            "pid", "ppid", "pppid", "name", "parent_name", "grandparent_name",
            "path", "user", "username", "cmdline",
            "state", "create_time", "exit_time", "wow64",
        ]
        assert rows[1][0] == "1234"
        assert rows[1][3] == "test.exe"  # name is index 3

    def test_handles_broken_process(self, tmp_path: Path):
        from extractors.processes import ProcessesExtractor

        bad_proc = MagicMock()
        bad_proc.pid = property(lambda _: (_ for _ in ()).throw(RuntimeError("boom")))
        type(bad_proc).pid = property(lambda _: (_ for _ in ()).throw(RuntimeError("boom")))

        vmm = MagicMock()
        vmm.process_list.return_value = [bad_proc]

        ext = ProcessesExtractor()
        result = ext.extract(vmm, tmp_path)
        assert result.ok is True
        assert result.rows == 0


class TestDllsExtractor:
    def test_extracts_modules(self, tmp_path: Path):
        from extractors.dlls import DllsExtractor

        mod = SimpleNamespace(
            name="ntdll.dll",
            fullpath=r"C:\Windows\System32\ntdll.dll",
            base=0x7FFE0000,
            size=1234,
            entry=0x7FFE0100,
        )
        proc = MagicMock()
        proc.pid = 100
        proc.name = "test.exe"
        proc.module_list.return_value = [mod]

        vmm = MagicMock()
        vmm.process_list.return_value = [proc]

        ext = DllsExtractor()
        result = ext.extract(vmm, tmp_path)
        assert result.ok is True
        assert result.rows == 1
        assert (tmp_path / "dlls.csv").exists()


class TestNetstatExtractor:
    def test_parses_netstat_text(self, tmp_path: Path):
        from extractors.netstat import NetstatExtractor

        netstat_text = textwrap.dedent("""\
            Proto  Local Address          Foreign Address        State           PID
            TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888
            TCP    10.0.0.5:49708         40.67.254.36:443       ESTABLISHED     4528
        """)
        vmm = _make_vmm_mock(vfs_files={"/sys/net/netstat.txt": netstat_text.encode()})

        ext = NetstatExtractor()
        result = ext.extract(vmm, tmp_path)
        assert result.ok is True
        assert result.rows == 2
        assert (tmp_path / "net.csv").exists()


class TestForensicCsvExtractors:
    """All forensic_csv extractors share the same pattern — test a few."""

    @pytest.mark.parametrize("module_name,csv_name", [
        ("extractors.modules", "modules.csv"),
        ("extractors.handles", "handles.csv"),
        ("extractors.threads", "threads.csv"),
        ("extractors.drivers", "drivers.csv"),
        ("extractors.devices", "devices.csv"),
        ("extractors.tasks", "tasks.csv"),
        ("extractors.findevil", "findevil.csv"),
        ("extractors.services", "services.csv"),
        ("extractors.unloaded_modules", "unloaded_modules.csv"),
    ])
    def test_copies_forensic_csv(self, tmp_path: Path, module_name: str, csv_name: str):
        import importlib
        mod = importlib.import_module(module_name)
        cls = None
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if isinstance(obj, type) and issubclass(obj, BaseExtractor) and obj is not BaseExtractor:
                cls = obj
                break
        assert cls is not None, f"No extractor found in {module_name}"

        content = b'"col1","col2"\n"v1","v2"\n'
        vmm = _make_vmm_mock(forensic_csvs={csv_name: content})
        result = cls().extract(vmm, tmp_path)
        assert result.ok is True
        assert (tmp_path / csv_name).exists()

    def test_missing_forensic_csv(self, tmp_path: Path):
        from extractors.modules import ModulesExtractor
        vmm = _make_vmm_mock(forensic_csvs={})
        result = ModulesExtractor().extract(vmm, tmp_path)
        assert result.ok is False


class TestTimelinesExtractor:
    def test_copies_all_timeline_files(self, tmp_path: Path):
        from extractors.timelines import TimelinesExtractor

        vmm = _make_vmm_mock(forensic_csvs={
            "timeline_all.csv": b'"h"\n"r"\n',
            "timeline_net.csv": b'"h"\n"r1"\n"r2"\n',
            "timeline_process.csv": b'"h"\n"r"\n',
            "process.csv": b'"h"\n"r"\n',
        })
        result = TimelinesExtractor().extract(vmm, tmp_path)
        assert result.ok is True
        assert len(result.files_written) == 3
        assert "timeline_all.csv" in result.files_written
        assert "process.csv" not in result.files_written


class TestTimelinesCoversRegistry:
    def test_covers_registry_csv(self, tmp_path: Path):
        from extractors.timelines import TimelinesExtractor

        vmm = _make_vmm_mock(forensic_csvs={
            "timeline_registry.csv": b'"h"\n"r"\n',
            "timeline_all.csv": b'"h"\n"r"\n',
        })
        result = TimelinesExtractor().extract(vmm, tmp_path)
        assert result.ok is True
        assert "timeline_registry.csv" in result.files_written
        assert (tmp_path / "timeline_registry.csv").exists()


# ── New field tests ──────────────────────────────────────────

class TestProcessesExtractorFields:
    def test_state_uses_proc_attribute(self, tmp_path: Path):
        from extractors.processes import ProcessesExtractor

        proc = SimpleNamespace(
            pid=1, ppid=0, name="p.exe", fullpath="", sid="", username="",
            cmdline="", state=5, time_create=None, time_exit=None, wow64=False,
        )
        vmm = MagicMock()
        vmm.process_list.return_value = [proc]

        result = ProcessesExtractor().extract(vmm, tmp_path)
        assert result.ok is True
        with (tmp_path / "process.csv").open(encoding="utf-8") as f:
            rows = list(csv.reader(f))
        state_idx = rows[0].index("state")
        assert rows[1][state_idx] == "5"

    def test_username_preferred_over_sid(self, tmp_path: Path):
        from extractors.processes import ProcessesExtractor

        proc = SimpleNamespace(
            pid=2, ppid=0, name="p.exe", fullpath="", sid="S-1-5-18",
            username="NT AUTHORITY\\SYSTEM", cmdline="",
            state=0, time_create=None, time_exit=None, wow64=False,
        )
        vmm = MagicMock()
        vmm.process_list.return_value = [proc]

        result = ProcessesExtractor().extract(vmm, tmp_path)
        with (tmp_path / "process.csv").open(encoding="utf-8") as f:
            rows = list(csv.reader(f))
        username_idx = rows[0].index("username")
        assert rows[1][username_idx] == "NT AUTHORITY\\SYSTEM"

    def test_time_direct_attributes(self, tmp_path: Path):
        from extractors.processes import ProcessesExtractor

        proc = SimpleNamespace(
            pid=3, ppid=0, name="p.exe", fullpath="", sid="", username="",
            cmdline="", state=0, time_create="2026-01-01", time_exit="2026-01-02",
            wow64=True,
        )
        vmm = MagicMock()
        vmm.process_list.return_value = [proc]

        result = ProcessesExtractor().extract(vmm, tmp_path)
        with (tmp_path / "process.csv").open(encoding="utf-8") as f:
            rows = list(csv.reader(f))
        ct_idx = rows[0].index("create_time")
        wow_idx = rows[0].index("wow64")
        assert rows[1][ct_idx] == "2026-01-01"
        assert rows[1][wow_idx] == "True"


class TestDllsExtractorFields:
    def test_pe_fields_captured(self, tmp_path: Path):
        from extractors.dlls import DllsExtractor

        pe_opt = SimpleNamespace(timedatestamp=12345, checksum=99)
        pefile = SimpleNamespace(opt=pe_opt)
        mod = SimpleNamespace(
            name="evil.dll", fullpath=r"C:\evil.dll",
            base=0x1000, size=4096, entry=0x1100,
            is_wow64=True, tp_file=1, pefile=pefile,
        )
        proc = MagicMock()
        proc.pid = 100
        proc.name = "host.exe"
        proc.module_list.return_value = [mod]

        vmm = MagicMock()
        vmm.process_list.return_value = [proc]

        result = DllsExtractor().extract(vmm, tmp_path)
        assert result.ok is True
        with (tmp_path / "dlls.csv").open(encoding="utf-8") as f:
            rows = list(csv.reader(f))
        h = rows[0]
        r = rows[1]
        assert r[h.index("is_wow64")] == "True"
        assert r[h.index("module_type")] == "1"
        assert r[h.index("pe_timedatestamp")] == "12345"
        assert r[h.index("pe_checksum")] == "99"


class TestNetstatExtractorFields:
    def test_process_name_column(self, tmp_path: Path):
        from extractors.netstat import NetstatExtractor

        netstat_text = textwrap.dedent("""\
            Proto  Local Address          Foreign Address        State           PID
            TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888
        """)
        vmm = _make_vmm_mock(vfs_files={"/sys/net/netstat.txt": netstat_text.encode()})

        proc888 = SimpleNamespace(pid=888, name="svchost.exe")
        vmm.process_list.return_value = [proc888]

        result = NetstatExtractor().extract(vmm, tmp_path)
        assert result.ok is True
        with (tmp_path / "net.csv").open(encoding="utf-8") as f:
            rows = list(csv.reader(f))
        pn_idx = rows[0].index("process_name")
        assert rows[1][pn_idx] == "svchost.exe"


# ── Orchestrator CLI ────────────────────────────────────────

class TestOrchestratorCli:
    def test_list_flag(self):
        from run_extract import main
        exit_code = main(["--list"])
        assert exit_code == 0

    def test_missing_args_errors(self):
        from run_extract import main
        with pytest.raises(SystemExit) as exc_info:
            main(["--dump", "fake.dmp"])
        assert exc_info.value.code != 0

    def test_resolve_extractors_only(self):
        from run_extract import resolve_extractors
        registry = {"a": "A", "b": "B", "c": "C"}
        result = resolve_extractors(registry, only="a,c", exclude=None)
        assert set(result) == {"a", "c"}

    def test_resolve_extractors_exclude(self):
        from run_extract import resolve_extractors
        registry = {"a": "A", "b": "B", "c": "C"}
        result = resolve_extractors(registry, only=None, exclude="b")
        assert set(result) == {"a", "c"}

    def test_resolve_extractors_all(self):
        from run_extract import resolve_extractors
        registry = {"a": "A", "b": "B"}
        result = resolve_extractors(registry, only=None, exclude=None)
        assert result == registry

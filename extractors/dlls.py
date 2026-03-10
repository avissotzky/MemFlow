"""Extract per-process loaded DLLs via the MemProcFS direct Python API.

Uses ``proc.module_list()`` to enumerate every loaded module for each
process, producing a flat CSV with one row per DLL per process.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)


class DllsExtractor(BaseExtractor):
    name = "dlls"
    output_filename = "dlls.csv"
    source = "api"

    HEADERS = [
        "pid", "process_name", "module_name", "module_path",
        "base_address", "size", "entry_point",
        "is_wow64", "module_type", "pe_timedatestamp", "pe_checksum",
    ]

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        rows: list[list[str]] = []
        for proc in vmm.process_list():
            try:
                pid = str(proc.pid)
                proc_name = proc.name or ""
                for mod in proc.module_list():
                    try:
                        mod_name = mod.name or ""
                        mod_path = mod.fullpath if hasattr(mod, "fullpath") else ""
                        base = hex(mod.base) if hasattr(mod, "base") else ""
                        size = str(mod.size) if hasattr(mod, "size") else ""
                        entry = hex(mod.entry) if hasattr(mod, "entry") else ""
                        is_wow64 = str(bool(getattr(mod, "is_wow64", False)))
                        module_type = str(getattr(mod, "tp_file", ""))
                        try:
                            pefile = getattr(mod, "pefile", None)
                            pe_opt = getattr(pefile, "opt", None) if pefile is not None else None
                            pe_ts = str(getattr(pe_opt, "timedatestamp", "")) if pe_opt is not None else ""
                            pe_ck = str(getattr(pe_opt, "checksum", "")) if pe_opt is not None else ""
                        except Exception:
                            pe_ts = ""
                            pe_ck = ""
                        rows.append([
                            pid, proc_name, mod_name, mod_path, base, size, entry,
                            is_wow64, module_type, pe_ts, pe_ck,
                        ])
                    except Exception as exc:
                        logger.debug("Skipping module in PID %s: %s", pid, exc)
            except Exception as exc:
                logger.debug("Skipping process for DLL enum: %s", exc)

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

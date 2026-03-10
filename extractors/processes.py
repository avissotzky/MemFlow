"""Extract the process list via the MemProcFS direct Python API."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)


class ProcessesExtractor(BaseExtractor):
    name = "processes"
    output_filename = "process.csv"
    source = "api"

    HEADERS = [
        "pid", "ppid", "name", "path", "user", "cmdline",
        "state", "create_time", "exit_time",
    ]

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        rows: list[list[str]] = []
        for proc in vmm.process_list():
            try:
                pid = str(proc.pid)
                ppid = str(proc.ppid)
                name = proc.name or ""
                try:
                    path = proc.fullpath or ""
                except Exception:
                    path = ""
                try:
                    user = proc.sid or ""
                except Exception:
                    user = ""
                try:
                    cmdline = proc.cmdline or ""
                except Exception:
                    cmdline = ""
                state_val = "Running"
                try:
                    ti = proc.info
                    create_time = str(ti.get("time-create", "")) if isinstance(ti, dict) else ""
                    exit_time = str(ti.get("time-exit", "")) if isinstance(ti, dict) else ""
                except Exception:
                    create_time = ""
                    exit_time = ""
                rows.append([
                    pid, ppid, name, path, user, cmdline,
                    state_val, create_time, exit_time,
                ])
            except Exception as exc:
                logger.warning("Skipping process: %s", exc)

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

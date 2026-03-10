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
        "pid", "ppid", "pppid", "name", "parent_name", "grandparent_name",
        "path", "user", "username", "cmdline",
        "state", "create_time", "exit_time", "wow64",
    ]

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        # Build pid → (name, ppid) lookup for parent/grandparent resolution
        pid_info: dict[str, tuple[str, str]] = {}
        try:
            for p in vmm.process_list():
                try:
                    pid_info[str(p.pid)] = (p.name or "", str(p.ppid))
                except Exception:
                    pass
        except Exception:
            pass

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
                    username = str(proc.username) if getattr(proc, "username", None) else ""
                except Exception:
                    username = ""
                try:
                    cmdline = proc.cmdline or ""
                except Exception:
                    cmdline = ""
                try:
                    state_val = str(getattr(proc, "state", ""))
                except Exception:
                    state_val = ""
                try:
                    create_time = str(proc.time_create) if getattr(proc, "time_create", None) else ""
                except Exception:
                    create_time = ""
                try:
                    exit_time = str(proc.time_exit) if getattr(proc, "time_exit", None) else ""
                except Exception:
                    exit_time = ""
                try:
                    wow64 = str(bool(getattr(proc, "wow64", False)))
                except Exception:
                    wow64 = ""
                parent_name, pppid_val, grandparent_name = "", "", ""
                if ppid in pid_info:
                    parent_name, pppid_val = pid_info[ppid]
                    if pppid_val in pid_info:
                        grandparent_name = pid_info[pppid_val][0]

                rows.append([
                    pid, ppid, pppid_val, name, parent_name, grandparent_name,
                    path, user, username, cmdline,
                    state_val, create_time, exit_time, wow64,
                ])
            except Exception as exc:
                logger.warning("Skipping process: %s", exc)

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

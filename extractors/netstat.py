"""Extract network connections by parsing the MemProcFS VFS netstat text."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)

VFS_NETSTAT = "/sys/net/netstat.txt"


class NetstatExtractor(BaseExtractor):
    name = "netstat"
    output_filename = "net.csv"
    source = "vfs"

    HEADERS = [
        "pid", "process_name", "protocol", "state",
        "src-addr", "src-port", "dst-addr", "dst-port",
    ]

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        rows: list[list[str]] = []
        try:
            pid_to_name: dict[str, str] = {}
            try:
                for proc in vmm.process_list():
                    try:
                        pid_to_name[str(proc.pid)] = proc.name or ""
                    except Exception:
                        pass
            except Exception:
                pass

            text = self.read_vfs_text(vmm, VFS_NETSTAT)
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("Proto"):
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue

                proto = parts[0]
                local = parts[1]
                remote = parts[2]
                state = parts[3] if len(parts) > 3 else ""
                pid = parts[4] if len(parts) > 4 else ""
                proc_name = pid_to_name.get(pid, "")

                local_parts = local.rsplit(":", 1)
                remote_parts = remote.rsplit(":", 1)
                src_addr = local_parts[0] if local_parts else ""
                src_port = local_parts[1] if len(local_parts) > 1 else ""
                dst_addr = remote_parts[0] if remote_parts else ""
                dst_port = remote_parts[1] if len(remote_parts) > 1 else ""

                rows.append([pid, proc_name, proto, state, src_addr, src_port, dst_addr, dst_port])
        except Exception as exc:
            logger.error("Netstat extraction failed: %s", exc)
            return ExtractResult(ok=False, error=str(exc))

        self.write_csv(out_dir, self.output_filename, self.HEADERS, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=[self.output_filename])

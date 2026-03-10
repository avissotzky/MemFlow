"""Extract all timeline CSVs from the forensic output.

MemProcFS produces a family of ``timeline_*.csv`` files (timeline_all,
timeline_ntfs, timeline_process, timeline_thread, timeline_task,
timeline_net, timeline_kernelobject, timeline_prefetch, timeline_web, etc.).
This extractor copies all of them in one pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult


class TimelinesExtractor(BaseExtractor):
    name = "timelines"
    output_filename = "timeline_all.csv"
    source = "forensic_csv"

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        return self.copy_forensic_csvs_matching(vmm, "timeline_", out_dir)

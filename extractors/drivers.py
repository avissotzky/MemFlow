"""Extract kernel drivers from the forensic CSV."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from extractors.base import BaseExtractor, ExtractResult


class DriversExtractor(BaseExtractor):
    name = "drivers"
    output_filename = "drivers.csv"
    source = "forensic_csv"

    def extract(self, vmm: Any, out_dir: Path) -> ExtractResult:
        return self.copy_forensic_csv(vmm, self.output_filename, out_dir)

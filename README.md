# MemFlow – Offline Forensic Correlation Engine

> **"CSV is the Source of Truth."**

MemFlow ingests raw CSV output from memory forensics tools (e.g. MemProcFS),
normalises the data losslessly, and produces typed, analysis-ready CSV files —
all without any external database.

## Quick Start

```bash
# 1. Clone & enter the project
cd MemFlow

# 2. Create a virtual environment (Python 3.10+)
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

# 3. Install the package (includes all dependencies)
pip install .

# 4. Run the test suite
python -m pytest tests/ -v
```

### Offline / Air-Gapped Install

Zip the project folder, transfer it to the target machine, then:

```bash
python -m venv .venv && .venv\Scripts\activate
pip install .
```

All console commands (see below) are now available on `PATH`.

## Console Commands

After `pip install .`, the following commands are available:

| Command | Tool |
|---------|------|
| `memflow-extract` | Plugin-based extractor (run all or selected abilities) |
| `memflow-ingest` | Ingest raw CSVs from MemProcFS output |
| `memflow-inventory` | Scan and discover existing tables |
| `memflow-parse-generic` | Convert Raw CSV → Typed CSV via specs |
| `memflow-validate` | Validate typed CSVs against specs |
| `memflow-spec-scaffold` | Generate YAML spec scaffolds |
| `memflow-entropy` | Entropy analysis |
| `memflow-alerts-injection` | Code injection detection |
| `memflow-alerts-lateral` | Lateral movement detection |
| `memflow-alerts-network` | Network anomaly detection |
| `memflow-alerts-persistence` | Persistence mechanism detection |
| `memflow-alerts-process` | Suspicious process detection |

Every command follows the standard CLI contract (`--case`, `--in`, `--out`, `--log-level`).

## Extractor Plugins

The `extractors/` package uses a plugin architecture. Each `.py` file defines
one extraction capability. The orchestrator (`run_extract.py`) auto-discovers
all plugins and runs them with a shared VMM session.

```bash
# Run all extractors
python run_extract.py --dump MEMORY.DMP --case case_demo

# Run only specific abilities
python run_extract.py --dump MEMORY.DMP --case case_demo --only processes,dlls,netstat

# Skip timelines (they are large)
python run_extract.py --dump MEMORY.DMP --case case_demo --exclude timelines

# List available extractors
python run_extract.py --list
```

### Adding a new extractor

Create a single file in `extractors/`, e.g. `extractors/vads.py`:

```python
from extractors.base import BaseExtractor, ExtractResult
from pathlib import Path

class VadsExtractor(BaseExtractor):
    name = "vads"
    output_filename = "vads.csv"
    source = "api"

    def extract(self, vmm, out_dir: Path) -> ExtractResult:
        headers = ["pid", "process", "start", "end", "protection", "tag"]
        rows = []
        for proc in vmm.process_list():
            # ... enumerate VADs ...
            pass
        self.write_csv(out_dir, self.output_filename, headers, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=["vads.csv"])
```

The orchestrator picks it up automatically on the next run.

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `extractors/` | Plugin-based data extractors (one file per ability) |
| `memflow_common/` | Shared I/O, logging, safe CSV handling |
| `memflow_parser/` | Raw CSV → Typed CSV conversion engine |
| `memflow_specs/` | YAML schema definitions for table types |
| `tools/` | Standalone entry-point scripts |
| `docs/` | Architecture & contract documentation |
| `tests/` | Unit and integration tests |

## CLI Contract

Every tool accepts the same standard arguments:

```
--case   (-c)   Root of the investigation directory
--in     (-i)   Input file or directory
--out    (-o)   Output directory (default: <case>/csv/)
--log-level (-l)  DEBUG | INFO | WARN | ERROR
```

See [docs/05_cli_contract.md](docs/05_cli_contract.md) for full details.

## License

Internal / proprietary — see project governance for details.

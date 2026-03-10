# MemFlow — Complete User Guide

> **"CSV is the Source of Truth."**

---

## Table of Contents

1. [What is MemFlow?](#1-what-is-memflow)
2. [Installation](#2-installation)
3. [Project Architecture](#3-project-architecture)
4. [The Data Pipeline](#4-the-data-pipeline)
5. [CLI Contract — Standard Arguments](#5-cli-contract--standard-arguments)
6. [Tool Reference](#6-tool-reference)
   - 6.0 [memflow-extract — Plugin-Based Data Extraction](#60-memflow-extract--plugin-based-data-extraction)
   - 6.1 [memflow-ingest — Memory Dump Extraction](#61-memflow-ingest--memory-dump-extraction-mf-010--mf-015)
   - 6.2 [memflow-inventory — CSV Discovery & Health Check](#62-memflow-inventory--csv-discovery--health-check-mf-020)
   - 6.3 [memflow-spec-scaffold — YAML Spec Generation](#63-memflow-spec-scaffold--yaml-spec-generation-mf-030)
   - 6.4 [memflow-parse-generic — Raw → Typed CSV Conversion](#64-memflow-parse-generic--raw--typed-csv-conversion-mf-050)
   - 6.5 [memflow-validate — Data Integrity Validation](#65-memflow-validate--data-integrity-validation-mf-070)
   - 6.6 [memflow-entropy — File Entropy & Hash Analysis](#66-memflow-entropy--file-entropy--hash-analysis-mf-080)
   - 6.7 [memflow-alerts-network — Network Anomaly Detection](#67-memflow-alerts-network--network-anomaly-detection-mf-101)
   - 6.8 [memflow-alerts-injection — Code Injection Detection](#68-memflow-alerts-injection--code-injection-detection-mf-102)
   - 6.9 [memflow-alerts-process — Suspicious Process Detection](#69-memflow-alerts-process--suspicious-process-detection-mf-103)
   - 6.10 [memflow-alerts-persistence — Persistence Mechanism Detection](#610-memflow-alerts-persistence--persistence-mechanism-detection-mf-104)
   - 6.11 [memflow-alerts-lateral — Lateral Movement Detection](#611-memflow-alerts-lateral--lateral-movement-detection-mf-105)
7. [Shared Libraries](#7-shared-libraries)
   - 7.1 [memflow_common — CSV I/O & Lossless Handling](#71-memflow_common--csv-io--lossless-handling)
   - 7.2 [memflow_parser — The Type Conversion Engine](#72-memflow_parser--the-type-conversion-engine)
8. [Complete Workflow — End-to-End Example](#8-complete-workflow--end-to-end-example)
9. [Directory Structure Reference](#9-directory-structure-reference)
10. [Exit Codes Reference](#10-exit-codes-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. What is MemFlow?

MemFlow is an **Offline Forensic Correlation Engine**. It takes raw CSV output from memory forensics tools — primarily **MemProcFS** — and transforms it into normalised, typed, analysis-ready CSV files. It then runs a suite of security alert detectors across that data.

**Key principles:**

- **CSV is the only data format** — no SQLite, no Parquet, no binary blobs.
- **Zero data loss** — every row is preserved; malformed rows are logged, never dropped.
- **Fully offline** — no internet required. No external databases. Pure Python 3.10+.
- **Standalone scripts** — each tool is a self-contained entry point with a uniform CLI.

---

## 2. Installation

### 2.1 Prerequisites

- **Python 3.10** or newer
- **pip** (bundled with Python)
- A raw memory dump file (`.raw`, `.dmp`, `.vmem`, etc.) for the ingestion step

### 2.2 Standard Installation

```bash
# Clone or extract the project
cd MemFlow

# Create a virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux / macOS)
# source .venv/bin/activate

# Install MemFlow and all dependencies
pip install .
```

### 2.3 Offline / Air-Gapped Installation

On a machine **with** internet access:

```bash
# Download all dependencies as wheel files
pip download . -d ./offline_packages
```

Transfer the entire project folder (including `offline_packages/`) to the target machine.

On the **offline** machine:

```bash
cd MemFlow
python -m venv .venv
.venv\Scripts\activate
pip install --no-index --find-links=./offline_packages .
```

### 2.4 Verify Installation

After installation, every tool is available as a command:

```bash
memflow-extract --list
memflow-ingest --help
memflow-inventory --help
memflow-parse-generic --help
memflow-validate --help
memflow-spec-scaffold --help
memflow-entropy --help
memflow-alerts-injection --help
memflow-alerts-lateral --help
memflow-alerts-network --help
memflow-alerts-persistence --help
memflow-alerts-process --help
```

### 2.5 Install Test Dependencies

```bash
pip install ".[test]"
python -m pytest tests/ -v
```

---

## 3. Project Architecture

```
MemFlow/
├── extractors/              # Plugin-based data extractors (one file per ability)
│   ├── __init__.py          # Auto-discovery of extractor plugins
│   ├── base.py              # BaseExtractor ABC + ExtractResult + shared helpers
│   ├── processes.py         # Process list (API)
│   ├── dlls.py              # Per-process loaded DLLs (API)
│   ├── netstat.py           # Network connections (VFS)
│   ├── modules.py           # Kernel modules (forensic CSV)
│   ├── handles.py           # Handle table (forensic CSV)
│   ├── files.py             # Open files (forensic CSV)
│   ├── threads.py           # Threads (forensic CSV)
│   ├── tasks.py             # Scheduled tasks (forensic CSV)
│   ├── drivers.py           # Kernel drivers (forensic CSV)
│   ├── devices.py           # Device objects (forensic CSV)
│   ├── unloaded_modules.py  # Unloaded modules (forensic CSV)
│   ├── findevil.py          # FindEvil results (forensic CSV)
│   ├── services.py          # Windows services (forensic CSV)
│   └── timelines.py         # All timeline_*.csv files incl. timeline_registry.csv (forensic CSV)
│
├── memflow_common/          # Shared I/O, logging, safe CSV handling
│   ├── __init__.py
│   └── csv_io.py            # RawTable, read_csv_safe, write_csv_safe
│
├── memflow_parser/          # Engine: Raw CSV → Typed CSV (via YAML Specs)
│   ├── __init__.py
│   └── engine.py            # load_spec, parse_table, convert_value
│
├── memflow_specs/           # Machine-readable YAML table definitions
│   └── __init__.py          # (YAML files generated by spec-scaffold)
│
├── tools/                   # Standalone entry-point scripts (11 tools)
│   ├── memflow_ingest.py
│   ├── memflow_inventory.py
│   ├── memflow_spec_scaffold.py
│   ├── memflow_parse_generic.py
│   ├── memflow_validate.py
│   ├── memflow_entropy.py
│   ├── memflow_alerts_injection.py
│   ├── memflow_alerts_lateral.py
│   ├── memflow_alerts_network.py
│   ├── memflow_alerts_persistence.py
│   └── memflow_alerts_process.py
│
├── run_extract.py           # Plugin orchestrator (runs all/selected extractors)
├── tests/                   # Unit and integration tests (192 tests)
├── docs/                    # Documentation
├── pyproject.toml           # Package configuration
├── requirements.txt         # Legacy dependency list
└── README.md
```

### Package Roles

| Package | Role |
|---------|------|
| `extractors` | Plugin-based data extractors — one file per MemProcFS capability, auto-discovered by orchestrator |
| `memflow_common` | Shared CSV read/write with lossless guarantees, encoding resilience, SHA-256 integrity tracking |
| `memflow_parser` | Type conversion engine — converts raw string values to int, float, bool, timestamp, hex_int |
| `memflow_specs` | Houses YAML spec files that define column types per table |
| `tools` | 11 standalone command-line tools — the user-facing entry points |

---

## 4. The Data Pipeline

MemFlow follows a strict sequential pipeline. Each stage feeds the next:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          THE MEMFLOW PIPELINE                          │
└─────────────────────────────────────────────────────────────────────────┘

  Memory Dump (.raw / .dmp)
         │
         ▼
  ┌──────────────┐
  │  1. INGEST   │  memflow-ingest
  │              │  Extract raw CSVs from MemProcFS virtual filesystem
  └──────────────┘
         │  outputs: <case>/csv/*.csv (raw)
         ▼
  ┌──────────────┐
  │ 2. INVENTORY │  memflow-inventory
  │              │  Scan CSVs, detect anomalies, create manifest
  └──────────────┘
         │  outputs: inventory JSON + manifest CSV
         ▼
  ┌──────────────┐
  │ 3. SCAFFOLD  │  memflow-spec-scaffold
  │              │  Generate YAML specs from inventory
  └──────────────┘
         │  outputs: memflow_specs/*.yaml
         ▼
  ┌──────────────┐
  │  4. PARSE    │  memflow-parse-generic
  │              │  Apply specs → convert Raw CSV to Typed CSV
  └──────────────┘
         │  outputs: <case>/csv/typed_*.csv
         ▼
  ┌──────────────┐
  │ 5. VALIDATE  │  memflow-validate
  │              │  Verify parity, constraints, cross-table relations
  └──────────────┘
         │  outputs: validation_report.md
         ▼
  ┌────────────────────────────────────────────────┐
  │              6. ANALYSIS TOOLS                  │
  │                                                │
  │  memflow-entropy          File entropy + hashes│
  │  memflow-alerts-network   Network anomalies    │
  │  memflow-alerts-injection Code injection       │
  │  memflow-alerts-process   Suspicious processes │
  │  memflow-alerts-persist.  Persistence mechs    │
  │  memflow-alerts-lateral   Lateral movement     │
  └────────────────────────────────────────────────┘
         │  outputs: <case>/csv/alerts_*.csv, file_entropy.csv
         ▼
     Analysis-ready artifacts
```

---

## 5. CLI Contract — Standard Arguments

Every tool follows the same CLI contract for consistency and scriptability.

### Standard Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Absolute or relative path to the investigation root directory. All output is written under this path. |
| `--in` | `-i` | Varies | — | Path to the input file **or** directory to process. |
| `--out` | `-o` | No | `<case>/csv/` | Path to the output directory. Created automatically if it does not exist. |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARN`, `ERROR`. |

### Rules

1. **`--case` is the anchor.** If `--out` is omitted, output defaults to `<case>/csv/`. Log files always go to `<case>/logs/`.
2. **`--in` may be a file or a directory.** When it is a directory, the tool processes every supported file inside it.
3. **`--out` is always a directory, never a file.** The tool decides output filenames.
4. **`--log-level` controls both console and file output.** At `DEBUG`, every row-level operation is logged. At `INFO`, only summaries.

### Standard Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — all rows processed (warnings may exist). |
| `1` | Partial failure — some data had issues, output was still produced. |
| `2` | Fatal — input not found, critical dependency missing, or output directory cannot be created. |

---

## 6. Tool Reference

---

### 6.0 memflow-extract — Plugin-Based Data Extraction

**Purpose:** Extract specific data types from a memory dump using a plugin architecture. Each extraction capability (processes, DLLs, threads, network, etc.) is a self-contained plugin. The orchestrator opens a single VMM session and runs all (or selected) plugins.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--dump` | `-d` | **Yes** | — | Path to the raw memory dump file |
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--out` | `-o` | No | `<case>/csv/` | Output directory for extracted CSVs |
| `--only` | — | No | — | Comma-separated list of extractors to run (e.g. `processes,dlls,netstat`) |
| `--exclude` | — | No | — | Comma-separated list of extractors to skip (e.g. `timelines`) |
| `--timeout` | `-t` | No | `300` | Seconds to wait for forensic CSV generation |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |
| `--list` | — | No | — | List all available extractors and exit |

#### Available Extractors

| Name | Source | Output | Description |
|------|--------|--------|-------------|
| `processes` | API | `process.csv` | Process list (PID, PPID, name, path, cmdline, SID, username, state, times, wow64) |
| `dlls` | API | `dlls.csv` | Per-process loaded DLLs (module name, path, base, size, entry, is_wow64, module_type, PE timestamps) |
| `netstat` | VFS | `net.csv` | Network connections (pid, process_name, protocol, addresses, ports, state) |
| `modules` | Forensic CSV | `modules.csv` | System-wide kernel modules |
| `handles` | Forensic CSV | `handles.csv` | Handle table |
| `files` | Forensic CSV | `files.csv` | Open files |
| `threads` | Forensic CSV | `threads.csv` | Thread information |
| `tasks` | Forensic CSV | `tasks.csv` | Scheduled tasks |
| `drivers` | Forensic CSV | `drivers.csv` | Kernel drivers |
| `devices` | Forensic CSV | `devices.csv` | Device objects |
| `unloaded_modules` | Forensic CSV | `unloaded_modules.csv` | Unloaded modules |
| `findevil` | Forensic CSV | `findevil.csv` | FindEvil scan results |
| `services` | Forensic CSV | `services.csv` | Windows services |
| `timelines` | Forensic CSV | `timeline_*.csv` | All timeline CSVs including timeline_registry.csv |

#### Source Strategies

| Source | How It Works |
|--------|-------------|
| **API** | Direct MemProcFS Python API (e.g. `vmm.process_list()`, `proc.module_list()`). No forensic mode needed. |
| **VFS** | Reads and parses a text file from the MemProcFS virtual filesystem (e.g. `/sys/net/netstat.txt`). |
| **Forensic CSV** | Copies pre-built CSVs from `/forensic/csv/`. Requires forensic mode (enabled automatically). |

#### Examples

**List available extractors:**

```bash
python run_extract.py --list
```

**Run all extractors:**

```bash
python run_extract.py \
    --dump C:\Evidence\memory.raw \
    --case C:\Cases\IR-2025-042
```

**Run only specific extractors:**

```bash
python run_extract.py \
    --dump C:\Evidence\memory.raw \
    --case C:\Cases\IR-2025-042 \
    --only processes,dlls,netstat
```

**Skip large timeline files:**

```bash
python run_extract.py \
    --dump C:\Evidence\memory.raw \
    --case C:\Cases\IR-2025-042 \
    --exclude timelines
```

#### Adding a New Extractor

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

The orchestrator auto-discovers it on the next run. No registration or config changes needed.

#### Exit Codes

| Code | When |
|------|------|
| `0` | All selected extractors succeeded |
| `1` | Some extractors failed (partial success) |
| `2` | Fatal: memprocfs missing, dump file not found, or no extractors selected |

---

### 6.1 memflow-ingest — Memory Dump Extraction (MF-010 / MF-015)

**Purpose:** Extract raw CSV files from a memory dump using MemProcFS. This is the entry point of the entire pipeline.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--device` | `-d` | **Yes** | — | Path to the raw memory dump file (`.raw`, `.dmp`, `.vmem`) |
| `--out` | `-o` | No | `<case>/csv/` | Output directory for extracted CSVs |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |
| `--wait` | `-w` | No | `15` | Maximum seconds to wait for MemProcFS to populate CSVs |
| `--full-dump` | — | No | `False` | Enable deep artifact extraction (MF-015) |

> **Note:** This tool uses `--device` instead of `--in` because the input is a memory dump, not a CSV.

#### How It Works

1. **Dependency check** — Verifies that the `memprocfs` Python package is installed. Exits with code 2 if missing.
2. **MemProcFS initialization** — Launches MemProcFS with flags: `-device <path>`, `-forensic 1`, `-forensic-scan-ranges 1`, `-csv`.
3. **Wait for readiness** — Polls the virtual filesystem every 2 seconds until the CSV directory (`/forensic/csv/`) appears, up to `--wait` seconds.
4. **Extract CSVs** — Copies every `.csv` file from the VFS to the output directory, reading in 1 MiB chunks.
5. **Deep extraction** (if `--full-dump`) — Extracts additional forensic artifacts (see below).

#### Deep Extraction (--full-dump)

When `--full-dump` is enabled, the tool performs four additional extraction stages:

| Stage | What It Extracts | Output Path |
|-------|-----------------|-------------|
| Registry hives | SYSTEM, SOFTWARE, SAM, SECURITY, plus all NTUSER.DAT files | `<case>/raw/registry/` |
| FindEvil analysis | Parses the FindEvil report for PIDs flagged as CRITICAL, HIGH, MALICIOUS, or ALERT | `<case>/docs/findevil_raw.txt` |
| Suspicious binaries | Minidumps and open-handle files for flagged PIDs + LSASS | `<case>/raw/dumps/`, `<case>/raw/files/` |
| Recovered files | Carved executables: `.exe`, `.dll`, `.ps1`, `.bat`, `.sys` | `<case>/raw/recovered_files/` |

> **Warning:** Deep extraction can use disk space approximately **2x the RAM image size**.

#### Examples

**Basic extraction:**

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device C:\Evidence\memory.raw
```

This will:
- Create `C:\Cases\IR-2025-042\` if it doesn't exist
- Extract all CSVs to `C:\Cases\IR-2025-042\csv\`
- Log to `C:\Cases\IR-2025-042\logs\`

**With custom output and extended wait:**

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device D:\Evidence\server_mem.dmp \
    --out C:\Cases\IR-2025-042\raw_csv \
    --wait 60 \
    --log-level DEBUG
```

**Full forensic extraction:**

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device C:\Evidence\memory.raw \
    --full-dump
```

After this, the case directory will contain:

```
C:\Cases\IR-2025-042\
├── csv\                     # All forensic CSVs
│   ├── process.csv
│   ├── net.csv
│   ├── registry.csv
│   └── ... (all MemProcFS CSVs)
├── raw\
│   ├── registry\            # Registry hives
│   │   ├── SYSTEM
│   │   ├── SOFTWARE
│   │   ├── SAM
│   │   └── SECURITY
│   ├── dumps\               # Process minidumps
│   │   ├── PID_1234\
│   │   └── PID_4567\
│   ├── files\               # Open-handle files per PID
│   └── recovered_files\     # Carved executables
├── docs\
│   └── findevil_raw.txt     # FindEvil report
└── logs\
    └── ingest_<timestamp>.log
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | All CSVs extracted successfully |
| `1` | Some CSV extractions failed (partial success) |
| `2` | Fatal: `memprocfs` not installed, device file not found, or CSV directory never appeared |

---

### 6.2 memflow-inventory — CSV Discovery & Health Check (MF-020)

**Purpose:** Scan a directory of CSVs, build a complete inventory of every table, and detect anomalies (empty files, duplicate headers, read errors).

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory to scan for CSV files |
| `--out` | `-o` | No | `<case>` | Output base directory |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### How It Works

1. Scans the input directory for all `*.csv` files.
2. For each file, reads it using `read_csv_safe()` and records:
   - File name, full path
   - Column headers
   - Row count
   - SHA-256 hash
   - Any anomalies
3. Produces a JSON inventory and a flat CSV manifest.

#### Anomaly Detection

The inventory automatically flags these issues:

| Anomaly | Description |
|---------|-------------|
| `empty_file` | The file has no header row at all (0 bytes or only whitespace) |
| `empty_data` | The file has headers but zero data rows |
| `duplicate_header: <X>` | Column header `X` appears more than once |
| `read_error: <msg>` | The file could not be parsed (corrupt, encoding issue) |
| `locked_by_os` | The file raised a `PermissionError` (locked by another process) |

#### Examples

**Basic inventory after ingestion:**

```bash
memflow-inventory \
    --case C:\Cases\IR-2025-042
```

This scans `C:\Cases\IR-2025-042\csv\` and produces:
- `C:\Cases\IR-2025-042\docs\03_csv_inventory.json`
- `C:\Cases\IR-2025-042\artifacts\_inventory_manifest.csv`

**Custom input directory:**

```bash
memflow-inventory \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\raw_csv \
    --log-level DEBUG
```

**Checking the manifest:**

The `_inventory_manifest.csv` contains one row per CSV file:

```csv
"file","row_count","columns","sha256","anomalies"
"process.csv","1842","pid,ppid,name,path,cmdline,user","a1b2c3...","none"
"net.csv","523","pid,protocol,local_addr,local_port,remote_addr,remote_port,state","d4e5f6...","none"
"empty_table.csv","0","col_a,col_b","789abc...","empty_data"
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | All CSVs scanned, no anomalies detected |
| `1` | At least one anomaly was detected |
| `2` | Fatal: scan directory does not exist |

---

### 6.3 memflow-spec-scaffold — YAML Spec Generation (MF-030)

**Purpose:** Automatically generate YAML specification files for every table found in the inventory. These specs define column types and are used by the parser.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/docs/03_csv_inventory.json` | Path to the inventory JSON |
| `--out` | `-o` | No | `memflow_specs/` | Output directory for YAML specs |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |
| `--overwrite` | — | No | `False` | Overwrite existing spec files |

#### How It Works

1. Reads the inventory JSON created by `memflow-inventory`.
2. For each table in the inventory:
   - Generates a YAML file named `<table_name>.yaml`.
   - Every column defaults to `type: "raw"` (passthrough, no conversion).
   - If a spec already exists, it is **skipped** (unless `--overwrite` is set).
3. Tables with no headers are skipped.

#### Generated YAML Format

For a table `process.csv` with headers `pid, ppid, name, path`:

```yaml
# MemFlow spec – process
# Auto-generated scaffold – edit types as needed.

table: "process"

columns:
  - name: "pid"
    type: "raw"
  - name: "ppid"
    type: "raw"
  - name: "name"
    type: "raw"
  - name: "path"
    type: "raw"
```

#### Editing Specs After Generation

After scaffolding, **you should manually edit the specs** to assign correct types. Supported types are:

| Type | Description | Example Input | Example Output |
|------|-------------|---------------|----------------|
| `raw` | No conversion (passthrough) | `"hello"` | `"hello"` |
| `string` | Same as raw | `"hello"` | `"hello"` |
| `int` | Decimal integer | `"1234"` | `"1234"` (validated) |
| `hex_int` | Hexadecimal → decimal | `"0xFF"` | `"255"` |
| `float` | Floating-point number | `"3.14"` | `"3.14"` (validated) |
| `bool` | Boolean | `"true"`, `"yes"`, `"1"` | `"True"` |
| `timestamp` | Date/time → ISO 8601 | `"2025/01/15 08:30:00"` | `"2025-01-15T08:30:00"` |

**Example of a manually edited spec:**

```yaml
table: "process"

columns:
  - name: "pid"
    type: "int"
  - name: "ppid"
    type: "int"
  - name: "name"
    type: "string"
  - name: "path"
    type: "string"
  - name: "create_time"
    type: "timestamp"
  - name: "is_wow64"
    type: "bool"
  - name: "base_address"
    type: "hex_int"
```

#### Examples

**Generate specs from inventory:**

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042
```

This reads `C:\Cases\IR-2025-042\docs\03_csv_inventory.json` and creates YAML files in `memflow_specs/`.

**Overwrite existing specs:**

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042 \
    --overwrite
```

**Custom output directory:**

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042 \
    --out C:\Cases\IR-2025-042\specs
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | Specs generated successfully |
| `2` | Fatal: inventory JSON not found or unreadable |

---

### 6.4 memflow-parse-generic — Raw → Typed CSV Conversion (MF-050)

**Purpose:** Apply YAML specifications to raw CSV files, converting string values to their proper types (int, float, timestamp, etc.) and producing typed output CSVs.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | **Yes** | — | Path to a raw CSV file **or** directory of CSVs |
| `--out` | `-o` | No | `<case>/csv/` | Output directory for typed CSVs |
| `--specs` | `-s` | No | `memflow_specs/` | Directory containing YAML spec files |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### How It Works

1. Collects the list of CSV files to process (single file or all `*.csv` in a directory).
2. For each CSV:
   - Looks for a matching spec: `process.csv` → `process.yaml`.
   - Reads the raw CSV using `read_csv_safe()`.
   - Applies type conversions column-by-column.
   - If a value cannot be converted, the **original raw value is preserved** and a `ParseError` is logged.
   - Writes the typed output to `typed_<table>.csv`.
   - Appends any conversion errors to `_parsing_errors.csv`.

#### The Zero-Loss Guarantee

**The output row count always equals the input row count.** No rows are ever dropped. If a cell cannot be converted, the raw value is kept and the error is recorded separately.

#### Spec Matching

The parser matches CSVs to specs by filename stem:

| CSV File | Expected Spec |
|----------|---------------|
| `process.csv` | `process.yaml` |
| `net.csv` | `net.yaml` |
| `registry.csv` | `registry.yaml` |
| `vad.csv` | `vad.yaml` |

If no matching spec is found, the file is **skipped** with exit code 2.

#### Output Files

| File | Description |
|------|-------------|
| `typed_<table>.csv` | The typed version of the raw CSV |
| `_parsing_errors.csv` | Accumulated conversion errors (append mode) |

The error CSV has these columns:

```csv
"source_file","row_index","column","raw_value","expected_type","error"
"process.csv","42","pid","not_a_number","int","invalid literal for int()"
```

#### Examples

**Parse a single file:**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\process.csv
```

Output: `C:\Cases\IR-2025-042\csv\typed_process.csv`

**Parse all CSVs in a directory:**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv
```

This will process every CSV that has a matching spec.

**Custom specs directory:**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv \
    --specs C:\Cases\IR-2025-042\custom_specs
```

**Debug mode (logs every row conversion):**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\process.csv \
    --log-level DEBUG
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | All files parsed without conversion errors |
| `1` | At least one file had conversion errors (errors logged, data still produced) |
| `2` | Fatal: spec not found, input file missing, or specs directory missing |

---

### 6.5 memflow-validate — Data Integrity Validation (MF-070)

**Purpose:** Verify that the typed CSVs are consistent and correct by running three categories of checks: parity, constraints, and cross-table relations.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory containing `typed_*.csv` files |
| `--out` | `-o` | No | `<case>/artifacts/` | Output directory for the validation report |
| `--specs` | `-s` | No | `memflow_specs/` | YAML specs directory |
| `--manifest` | `-m` | No | `<case>/artifacts/_inventory_manifest.csv` | Path to the inventory manifest |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### Validation Checks

**1. Parity Check**

Ensures that every typed CSV has the same row count as reported in the inventory manifest. If `process.csv` had 1842 rows, then `typed_process.csv` must also have 1842 rows.

**2. Constraint Check**

For each typed CSV with a matching spec, verifies that columns with non-raw/non-string types contain non-null values. For example, if `pid` is `type: "int"`, every row must have a value in that column.

**3. Relation Check**

Cross-table referential integrity. Currently checks:
- Every `pid` in `typed_net.csv` must exist in `typed_process.csv`.

#### Output — Validation Report

The tool produces a Markdown report at `<out>/validation_report.md`:

```markdown
# MemFlow Validation Report

## Parity Checks
| Table | Status | Raw Rows | Typed Rows |
|-------|--------|----------|------------|
| process | PASS | 1842 | 1842 |
| net | PASS | 523 | 523 |

## Constraint Checks
| Table | Column | Status | Details |
|-------|--------|--------|---------|
| process | pid | PASS | — |
| process | create_time | FAIL | 3 null values |

## Relation Checks
| Check | Status | Details |
|-------|--------|---------|
| net.pid → process.pid | PASS | — |
```

#### Examples

**Basic validation:**

```bash
memflow-validate \
    --case C:\Cases\IR-2025-042
```

**Custom manifest and specs:**

```bash
memflow-validate \
    --case C:\Cases\IR-2025-042 \
    --manifest C:\Cases\IR-2025-042\artifacts\_inventory_manifest.csv \
    --specs C:\Cases\IR-2025-042\specs
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | All checks pass |
| `1` | At least one check failed |
| `2` | Fatal: typed directory or manifest not found |

---

### 6.6 memflow-entropy — File Entropy & Hash Analysis (MF-080)

**Purpose:** Calculate Shannon entropy, MD5, and SHA-256 hashes for files referenced in a CSV. High entropy (close to 8.0) can indicate packed, encrypted, or compressed binaries — common in malware.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | **Yes** | — | Path to `files.csv` or `typed_files.csv` |
| `--out` | `-o` | No | `<case>/csv/` | Output directory |
| `--forensic-dir` | `-f` | No | `<case>/forensic_files/` | Directory containing the actual files referenced in the CSV |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### How It Works

1. Reads the input CSV and identifies the file path column (tries: `file`, `filepath`, `path`, `name`, etc.).
2. For each row, resolves the file path:
   - First tries the path as-is (absolute).
   - Then tries relative to `--forensic-dir`.
   - Then tries just the basename in `--forensic-dir`.
3. Reads each file and computes:
   - **Shannon entropy** (0.0 – 8.0 scale)
   - **MD5 hash**
   - **SHA-256 hash**
   - **File size** in bytes
4. Writes results to `file_entropy.csv`.

#### Understanding Entropy Values

| Entropy Range | Interpretation |
|---------------|---------------|
| 0.0 – 1.0 | Very low — likely empty or repetitive data |
| 1.0 – 4.0 | Low — plain text, simple data |
| 4.0 – 6.0 | Medium — typical executables, documents |
| 6.0 – 7.0 | High — compiled code, some compression |
| 7.0 – 7.99 | Very high — packed, encrypted, or compressed (suspicious) |
| 8.0 | Maximum — perfectly random data (strong encryption or packing) |

#### Output Columns

```csv
"file_path","file_id","entropy","md5","sha256","file_size","status"
"C:\Windows\System32\svchost.exe","12","5.42","abc123...","def456...","51200","ok"
"C:\Temp\payload.bin","","7.98","789abc...","012def...","32768","ok"
"C:\missing.dll","15","","","","","not_found"
```

| Column | Description |
|--------|-------------|
| `file_path` | Original path from the input CSV |
| `file_id` | File ID from input CSV (if available) |
| `entropy` | Shannon entropy (0.0–8.0) |
| `md5` | MD5 hash |
| `sha256` | SHA-256 hash |
| `file_size` | File size in bytes |
| `status` | `ok`, `not_found`, or `read_error` |

#### Examples

**Basic entropy analysis:**

```bash
memflow-entropy \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\typed_files.csv
```

**With custom forensic files directory:**

```bash
memflow-entropy \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\files.csv \
    --forensic-dir C:\Cases\IR-2025-042\raw\recovered_files
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | All files processed successfully |
| `1` | Some files were not found or had read errors |
| `2` | Fatal: input CSV not found |

---

### 6.7 memflow-alerts-network — Network Anomaly Detection (MF-101)

**Purpose:** Detect suspicious network activity by analysing process-to-port relationships, listening services, high-port external connections, and DNS queries.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory with typed CSVs |
| `--out` | `-o` | No | `<case>/csv/` | Output directory |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### Required Input Files

| File | Required | Purpose |
|------|----------|---------|
| `typed_net.csv` | **Yes** | Network connection data |
| `typed_process.csv` | **Yes** | Process data for PID correlation |
| `typed_dns.csv` | No | DNS query data (enhances detection) |

#### Detection Rules

**Rule 1: PROCESS_PORT_MISMATCH (MEDIUM)**

A non-browser process communicating on port 80 or 443. Browsers (Chrome, Firefox, Edge, etc.) are excluded.

*Example:* `cmd.exe` connecting to port 443 → alert.

**Rule 2: LISTENER_TRAP (HIGH)**

A process in LISTENING state that is not on the approved listener list. Approved listeners include: `svchost.exe`, `spoolsv.exe`, `System`, `lsass.exe`, etc.

*Example:* `evil.exe` listening on port 4444 → alert.

**Rule 3: HIGH_PORT_EXTERNAL (MEDIUM)**

A connection to a non-private IP address on a port > 1024. Private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x) are excluded.

*Example:* Process connecting to `185.143.42.1:8443` → alert.

**Rule 4: RARE_DNS_QUERY (HIGH)**

PowerShell, cmd.exe, or pwsh.exe performing DNS resolution. These processes rarely need to resolve DNS directly.

*Example:* `powershell.exe` querying `evil-c2-server.com` → alert.

#### Output Columns

```csv
"alert_type","severity","pid","process_name","local_addr","local_port","remote_addr","remote_port","protocol","description"
```

#### Examples

```bash
memflow-alerts-network \
    --case C:\Cases\IR-2025-042
```

```bash
memflow-alerts-network \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv \
    --out C:\Cases\IR-2025-042\alerts \
    --log-level DEBUG
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | No network alerts |
| `1` | At least one alert generated |
| `2` | Fatal: `typed_net.csv` or `typed_process.csv` missing |

---

### 6.8 memflow-alerts-injection — Code Injection Detection (MF-102)

**Purpose:** Detect code injection techniques: shellcode injection (RWX unbacked memory), process hollowing, DKOM hidden processes, and reflective DLL loading.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory with typed CSVs |
| `--out` | `-o` | No | `<case>/csv/` | Output directory |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### Required Input Files

| File | Required | Purpose |
|------|----------|---------|
| `typed_findevil.csv` | Preferred | FindEvil results with VAD analysis |
| `typed_vad.csv` | Fallback | Virtual Address Descriptor data |
| `typed_process.csv` | For DKOM | Process list for hidden process detection |

#### Detection Rules

**Rule 1: RWX_UNBACKED (CRITICAL)**

A memory region with `PAGE_EXECUTE_READWRITE` protection that is **not backed by a file on disk**. This is the most common indicator of shellcode injection.

Unbacked sentinels: empty string, `-`, `n/a`, `none`, `unknown`, `private`, `pagefile-backed`.

**Rule 2: PROCESS_HOLLOWING (CRITICAL)**

A well-known system process (svchost, lsass, csrss, explorer, services, etc.) whose Image section points to an unexpected path or is empty. This indicates the legitimate process was hollowed out and replaced with malicious code.

Checked against canonical paths (e.g., `svchost.exe` must be in `\Windows\System32\`).

**Rule 3: DKOM_HIDDEN_PROCESS (CRITICAL)**

A PID appears in the FindEvil/VAD data but does **not** appear in `typed_process.csv`. This suggests the process has been hidden using Direct Kernel Object Manipulation (rootkit technique).

**Rule 4: REFLECTIVE_DLL (HIGH)**

A memory region containing an MZ header (PE executable signature) but with no backing file. This indicates a DLL was loaded directly into memory without touching disk — a common evasion technique.

#### Output Columns

```csv
"alert_type","severity","pid","process_name","address","size","protection","backing_file","source_table","description"
```

#### Examples

```bash
memflow-alerts-injection \
    --case C:\Cases\IR-2025-042
```

```bash
memflow-alerts-injection \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv \
    --log-level DEBUG
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | No injection alerts |
| `1` | At least one alert generated |
| `2` | Fatal: neither `typed_findevil.csv` nor `typed_vad.csv` found |

---

### 6.9 memflow-alerts-process — Suspicious Process Detection (MF-103)

**Purpose:** Detect process anomalies: path masquerading, parent-child mismatches, typosquatting of system binary names, and SID mismatches.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory with `typed_process.csv` |
| `--out` | `-o` | No | `<case>/csv/` | Output directory |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### Required Input Files

| File | Required |
|------|----------|
| `typed_process.csv` | **Yes** |

#### Detection Rules

**Rule 1: PATH_MASQUERADE (HIGH)**

A process with a system binary name (svchost, csrss, lsass, services, smss, wininit, winlogon) running from a path **outside** `C:\Windows\System32\`. Attackers often name their malware after system processes but place them in other directories.

*Example:* `C:\Users\Public\svchost.exe` → alert.

**Rule 2: PARENT_CHILD_MISMATCH (HIGH)**

Known parent-child relationships are violated:
- `svchost.exe` must be spawned by `services.exe`.
- Office applications (`winword.exe`, `excel.exe`, `outlook.exe`, etc.) should not spawn `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, or `mshta.exe`.

*Example:* `outlook.exe` → `powershell.exe` → alert.

**Rule 3: TYPOSQUATTING (MEDIUM)**

A process name has a Levenshtein distance < 2 from a critical system binary name. Attackers use names like `svhost.exe` or `lssas.exe` to blend in.

*Example:* `scvhost.exe` (distance 1 from `svchost.exe`) → alert.

**Rule 4: SID_MISMATCH (HIGH)**

System-only processes (`lsass.exe`, `csrss.exe`, `smss.exe`, `wininit.exe`, `services.exe`) not running under the SYSTEM account (NT AUTHORITY\SYSTEM / S-1-5-18).

*Example:* `lsass.exe` running as user `john` → alert.

#### Output Columns

```csv
"alert_type","severity","pid","process_name","ppid","parent_name","path","user","description"
```

#### Examples

```bash
memflow-alerts-process \
    --case C:\Cases\IR-2025-042
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | No process alerts |
| `1` | At least one alert generated |
| `2` | Fatal: `typed_process.csv` not found |

---

### 6.10 memflow-alerts-persistence — Persistence Mechanism Detection (MF-104)

**Purpose:** Detect persistence mechanisms in registry Run keys, services, and scheduled tasks.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory with typed CSVs |
| `--out` | `-o` | No | `<case>/csv/` | Output directory |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### Required Input Files (at least one)

| File | Purpose |
|------|---------|
| `typed_registry.csv` | Registry key analysis |
| `typed_services.csv` | Service binary analysis |
| `typed_tasks.csv` | Scheduled task analysis |

#### Detection Rules

**Rule 1: SUSPICIOUS_RUN_KEY (HIGH)**

A registry Run or RunOnce key whose value points to a suspicious path:
- `%TEMP%`
- `%APPDATA%`
- `\AppData\`
- `\Users\`
- `\ProgramData\`
- `\Downloads\`

*Example:* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `C:\Users\john\AppData\Local\Temp\backdoor.exe` → alert.

**Rule 2: SERVICE_MASQUERADE (HIGH)**

A Windows service whose binary path contains a suspicious executable:
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `mshta.exe`
- `wscript.exe`
- `rundll32.exe`

*Example:* Service `UpdateHelper` with path `powershell.exe -enc <base64>` → alert.

**Rule 3: HIDDEN_SCHEDULED_TASK (MEDIUM)**

A scheduled task with a suspicious action:
- `cmd /c` prefix
- `powershell -w hidden`
- `powershell -enc` (encoded command)
- `mshta` invocations

*Example:* Task `SystemUpdate` running `powershell.exe -w hidden -enc SQBFAFgA...` → alert.

#### Output Columns

```csv
"alert_type","severity","source","key_or_name","value_or_path","description"
```

#### Examples

```bash
memflow-alerts-persistence \
    --case C:\Cases\IR-2025-042
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | No persistence alerts |
| `1` | At least one alert generated |
| `2` | Fatal: none of the three required CSVs found |

---

### 6.11 memflow-alerts-lateral — Lateral Movement Detection (MF-105)

**Purpose:** Detect lateral movement techniques: credential dumping, reconnaissance command bursts, and remote execution patterns.

#### Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Investigation root directory |
| `--in` | `-i` | No | `<case>/csv/` | Directory with `typed_process.csv` |
| `--out` | `-o` | No | `<case>/csv/` | Output directory |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity |

#### Required Input Files

| File | Required |
|------|----------|
| `typed_process.csv` | **Yes** |

#### Detection Rules

**Rule 1: CREDENTIAL_DUMP (CRITICAL)**

Command-line patterns associated with credential theft:
- `mimikatz` or `sekurlsa`
- `procdump` targeting `lsass`
- `comsvcs.dll` with `MiniDump`
- `reg save` of SAM or SECURITY hives

*Example:* `procdump.exe -ma lsass.exe dump.dmp` → CRITICAL alert.

**Rule 2: RECON_COMMANDS (LOW → HIGH)**

Individual reconnaissance commands generate LOW severity alerts. When **3 or more distinct recon commands** originate from the same parent process, all are escalated to HIGH severity ("recon burst").

Detected recon commands:
- `net user`, `net group`, `net localgroup`
- `whoami /all`
- `ipconfig /all`
- `systeminfo`
- `nltest`
- `dsquery`
- `arp -a`
- `netstat`
- `tasklist`
- `qwinsta` / `query user`

*Example:* `cmd.exe` (PID 5678) spawned by the same parent runs `whoami`, `ipconfig`, `net user`, `systeminfo` → all escalated to HIGH.

**Rule 3: REMOTE_EXECUTION (HIGH)**

A remote execution service process spawning a shell:

| Parent (Remote Service) | Child (Shell) |
|------------------------|---------------|
| `wmiprvse.exe` | `cmd.exe` |
| `wmiapsrv.exe` | `powershell.exe` |
| `services.exe` | `pwsh.exe` |
| `wsmprovhost.exe` | — |

*Example:* `wmiprvse.exe` → `powershell.exe` → HIGH alert (WMI lateral movement).

#### Output Columns

```csv
"alert_type","severity","pid","process_name","ppid","parent_name","cmdline","description"
```

#### Examples

```bash
memflow-alerts-lateral \
    --case C:\Cases\IR-2025-042
```

```bash
memflow-alerts-lateral \
    --case C:\Cases\IR-2025-042 \
    --log-level DEBUG
```

#### Exit Codes

| Code | When |
|------|------|
| `0` | No lateral movement alerts |
| `1` | At least one alert generated |
| `2` | Fatal: `typed_process.csv` not found |

---

## 7. Shared Libraries

### 7.1 memflow_common — CSV I/O & Lossless Handling

This library provides the core CSV reading and writing functions used by all tools.

#### Key Data Structures

**`RawTable`** (dataclass):
- `source_path` — Path to the source file
- `headers` — List of column header strings
- `rows` — List of lists (all values are strings)
- `ingest_errors` — List of `IngestError` objects
- `sha256` — SHA-256 hash of the raw file
- `raw_row_count` — Number of data rows in the original file

**`IngestError`** (dataclass):
- `line_number` — Line number in the source file
- `raw_line` — The verbatim malformed line
- `error` — Description of the error

#### Functions

**`read_csv_safe(path) → RawTable`**

Reads a CSV file with full lossless guarantees:
- Tries `utf-8-sig` encoding first, falls back to `latin-1`.
- Short rows are padded with empty strings (never crashes).
- Extra columns are logged as ingest errors.
- Blank lines are skipped.
- Computes SHA-256 hash and records raw row count.

**`read_csv_safe_linewise(path) → RawTable`**

Line-by-line fallback reader for extremely malformed files.

**`write_csv_safe(path, headers, rows)`**

Writes a CSV file with `csv.QUOTE_ALL` (every field quoted). Creates parent directories if needed.

**`write_ingest_errors(path, errors) → Path | None`**

Writes ingest errors to `_ingest_errors.csv`. Returns `None` if there are no errors.

### 7.2 memflow_parser — The Type Conversion Engine

This library powers the Raw → Typed CSV conversion.

#### Supported Types

| Type | Conversion Logic |
|------|-----------------|
| `raw` / `string` | Passthrough — no conversion |
| `int` | `int(value.strip())` — rejects floats |
| `hex_int` | Handles `0x` prefix and bare hex |
| `float` | `float(value.strip())` |
| `bool` | `true/yes/1` → `True`, `false/no/0` → `False` |
| `timestamp` | Tries multiple formats, including Unix epoch |

#### Timestamp Parsing Order

The parser tries these formats in order:

1. `%Y-%m-%dT%H:%M:%S.%f` (ISO with microseconds)
2. `%Y-%m-%dT%H:%M:%S` (ISO)
3. `%Y/%m/%d %H:%M:%S` (slash-separated)
4. `%m/%d/%Y` (US date)
5. Unix epoch in seconds (if numeric, 10 digits)
6. Unix epoch in milliseconds (if numeric, 13 digits)

All timestamps are output in ISO 8601 format: `2025-01-15T08:30:00`.

#### Key Functions

**`load_spec(path) → TableSpec`**

Parses a YAML spec file using regex (no PyYAML dependency). Returns a `TableSpec` with table name and column definitions.

**`convert_value(value, type_name) → str | ParseError`**

Converts a single string value to the specified type. Returns the converted string on success, or a `ParseError` on failure.

**`parse_table(raw_table, spec) → TypedTable`**

Applies a spec to an entire `RawTable`. Returns a `TypedTable` with the same row count. Errors are collected in `parse_errors`, never cause row drops.

---

## 8. Complete Workflow — End-to-End Example

This section walks through a complete forensic analysis from memory dump to alerts.

### Scenario

You have a memory dump from an incident response: `C:\Evidence\compromised_server.raw`

Your case directory will be: `C:\Cases\IR-2025-042`

### Step 1: Ingest the Memory Dump

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device C:\Evidence\compromised_server.raw \
    --full-dump \
    --wait 30
```

**What happens:**
- MemProcFS analyses the memory dump
- All forensic CSVs are extracted to `C:\Cases\IR-2025-042\csv\`
- Registry hives, suspicious binaries, recovered files are extracted
- FindEvil report is saved

### Step 2: Inventory the Extracted Data

```bash
memflow-inventory \
    --case C:\Cases\IR-2025-042
```

**What happens:**
- Every CSV in `csv/` is scanned
- Anomalies are detected (empty files, duplicates, errors)
- `docs/03_csv_inventory.json` and `artifacts/_inventory_manifest.csv` are created

**Check for issues:**

```bash
# Look at the manifest to see what was found
type C:\Cases\IR-2025-042\artifacts\_inventory_manifest.csv
```

### Step 3: Generate YAML Specs

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042
```

**What happens:**
- A YAML spec is created for every table in the inventory
- All columns default to `type: "raw"`

**Now edit the specs** to assign proper types:

Open `memflow_specs/process.yaml` and change:

```yaml
columns:
  - name: "pid"
    type: "int"          # was "raw"
  - name: "ppid"
    type: "int"          # was "raw"
  - name: "name"
    type: "string"
  - name: "path"
    type: "string"
  - name: "create_time"
    type: "timestamp"    # was "raw"
```

Repeat for `net.yaml`, `registry.yaml`, `vad.yaml`, etc.

### Step 4: Parse Raw CSVs into Typed CSVs

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv
```

**What happens:**
- Each raw CSV is converted to `typed_<table>.csv`
- Type conversions are applied (strings → ints, timestamps, etc.)
- Conversion errors are logged to `_parsing_errors.csv`

### Step 5: Validate the Typed Data

```bash
memflow-validate \
    --case C:\Cases\IR-2025-042
```

**What happens:**
- Row counts are verified (parity check)
- Typed columns are checked for null values (constraint check)
- Cross-table PIDs are verified (relation check)
- A Markdown report is written to `artifacts/validation_report.md`

### Step 6: Run Entropy Analysis

```bash
memflow-entropy \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\typed_files.csv \
    --forensic-dir C:\Cases\IR-2025-042\raw\recovered_files
```

**What happens:**
- Each file referenced in the CSV is read
- Shannon entropy, MD5, SHA-256 are computed
- Results are written to `csv/file_entropy.csv`
- Files with entropy > 7.0 warrant further investigation

### Step 7: Run All Alert Detectors

```bash
# Network anomalies
memflow-alerts-network \
    --case C:\Cases\IR-2025-042

# Code injection
memflow-alerts-injection \
    --case C:\Cases\IR-2025-042

# Suspicious processes
memflow-alerts-process \
    --case C:\Cases\IR-2025-042

# Persistence mechanisms
memflow-alerts-persistence \
    --case C:\Cases\IR-2025-042

# Lateral movement
memflow-alerts-lateral \
    --case C:\Cases\IR-2025-042
```

### Step 8: Review Results

After running all tools, your case directory looks like:

```
C:\Cases\IR-2025-042\
├── csv\
│   ├── process.csv              # Raw
│   ├── net.csv                  # Raw
│   ├── registry.csv             # Raw
│   ├── ... (other raw CSVs)
│   ├── typed_process.csv        # Typed
│   ├── typed_net.csv            # Typed
│   ├── typed_registry.csv       # Typed
│   ├── ... (other typed CSVs)
│   ├── file_entropy.csv         # Entropy results
│   ├── alerts_network.csv       # Network alerts
│   ├── alerts_injection.csv     # Injection alerts
│   ├── alerts_process.csv       # Process alerts
│   ├── alerts_persistence.csv   # Persistence alerts
│   ├── alerts_lateral.csv       # Lateral movement alerts
│   ├── _parsing_errors.csv      # Conversion errors
│   └── _inventory_manifest.csv  # Inventory manifest
├── raw\
│   ├── registry\                # Extracted registry hives
│   ├── dumps\                   # Process minidumps
│   ├── files\                   # Open-handle files
│   └── recovered_files\         # Carved executables
├── artifacts\
│   ├── _inventory_manifest.csv
│   └── validation_report.md
├── docs\
│   ├── 03_csv_inventory.json
│   └── findevil_raw.txt
└── logs\
    └── *.log
```

### Automation Script

You can chain all steps into a single batch/PowerShell script:

```powershell
$CASE = "C:\Cases\IR-2025-042"
$DEVICE = "C:\Evidence\compromised_server.raw"

# Pipeline
memflow-ingest       -c $CASE -d $DEVICE --full-dump --wait 30
memflow-inventory    -c $CASE
memflow-spec-scaffold -c $CASE
# (edit specs manually here, or use pre-prepared specs)
memflow-parse-generic -c $CASE -i "$CASE\csv"
memflow-validate     -c $CASE

# Analysis
memflow-entropy           -c $CASE -i "$CASE\csv\typed_files.csv"
memflow-alerts-network    -c $CASE
memflow-alerts-injection  -c $CASE
memflow-alerts-process    -c $CASE
memflow-alerts-persistence -c $CASE
memflow-alerts-lateral    -c $CASE

Write-Host "Pipeline complete. Check $CASE for results."
```

---

## 9. Directory Structure Reference

### Case Directory Layout

| Path | Created By | Description |
|------|-----------|-------------|
| `<case>/csv/` | ingest, parse | Raw and typed CSV files |
| `<case>/csv/typed_*.csv` | parse-generic | Typed versions of raw CSVs |
| `<case>/csv/alerts_*.csv` | alert tools | Security alert results |
| `<case>/csv/file_entropy.csv` | entropy | Entropy analysis results |
| `<case>/csv/_parsing_errors.csv` | parse-generic | Type conversion errors |
| `<case>/csv/_ingest_errors.csv` | ingest | Raw CSV ingestion errors |
| `<case>/artifacts/` | inventory, validate | Reports and manifests |
| `<case>/artifacts/_inventory_manifest.csv` | inventory | Flat inventory of all CSVs |
| `<case>/artifacts/validation_report.md` | validate | Validation check results |
| `<case>/docs/` | inventory, ingest | Documentation artifacts |
| `<case>/docs/03_csv_inventory.json` | inventory | Full JSON inventory |
| `<case>/docs/findevil_raw.txt` | ingest (--full-dump) | FindEvil report |
| `<case>/raw/registry/` | ingest (--full-dump) | Extracted registry hives |
| `<case>/raw/dumps/` | ingest (--full-dump) | Process minidumps |
| `<case>/raw/files/` | ingest (--full-dump) | Open-handle files |
| `<case>/raw/recovered_files/` | ingest (--full-dump) | Carved executables |
| `<case>/logs/` | all tools | Per-run log files |

---

## 10. Exit Codes Reference

| Code | Meaning | Action |
|------|---------|--------|
| `0` | **Success** — all operations completed without issues | Continue to next pipeline step |
| `1` | **Partial failure** — output was produced, but with warnings/errors | Review error logs, continue with caution |
| `2` | **Fatal** — cannot continue (missing input, missing dependency) | Fix the problem before retrying |

### Per-Tool Exit Code Details

| Tool | Exit 0 | Exit 1 | Exit 2 |
|------|--------|--------|--------|
| `memflow-ingest` | All CSVs extracted | Some extractions failed | memprocfs missing, device missing, VFS timeout |
| `memflow-inventory` | No anomalies | Anomalies detected | Scan directory missing |
| `memflow-spec-scaffold` | Specs generated | — | Inventory JSON missing |
| `memflow-parse-generic` | No conversion errors | Conversion errors (data still produced) | Spec/input missing |
| `memflow-validate` | All checks pass | Check failures | Typed dir/manifest missing |
| `memflow-entropy` | All files processed | Some files not found | Input CSV missing |
| `memflow-alerts-*` | No alerts | Alerts generated | Required input CSV missing |

---

## 11. Troubleshooting

### "memprocfs not installed"

```
ERROR: memprocfs package is required for ingestion. Install with: pip install memprocfs
```

**Solution:** Run `pip install memprocfs` or `pip install .` from the project root.

### "CSV directory never appeared within N seconds"

The MemProcFS virtual filesystem did not produce CSV output in time.

**Solutions:**
- Increase the wait time: `--wait 60`
- Verify the memory dump file is valid and not corrupted
- Ensure sufficient RAM is available (MemProcFS needs memory to analyse the dump)

### "No matching spec found for X.csv"

The parser cannot find a YAML spec for the given CSV file.

**Solutions:**
- Run `memflow-spec-scaffold` first to generate specs
- Check that the spec filename matches the CSV filename (e.g., `process.csv` → `process.yaml`)
- Verify the `--specs` directory is correct

### "Empty data" anomaly in inventory

A CSV file has headers but zero data rows.

**This is informational, not necessarily an error.** Some MemProcFS tables may legitimately be empty if the corresponding data was not present in the memory dump.

### Encoding issues

MemFlow tries `utf-8-sig` first, then falls back to `latin-1`. If you still see garbled text:

- Check the source CSV encoding
- MemFlow will **never crash** on encoding errors — worst case, characters may display incorrectly but all data is preserved

### High entropy files

If `file_entropy.csv` shows files with entropy > 7.5:

- This does **not** automatically mean the file is malicious
- Compressed files (`.zip`, `.7z`), encrypted files, and packed executables all have high entropy
- Cross-reference with the alerts and process analysis for context

---

*Document version: 1.0 — Phase 6 Distribution*
*Generated for MemFlow v0.6.0*

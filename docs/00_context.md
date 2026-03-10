# MemFlow – Project Context & Architecture

## Overview

**MemFlow** is an Offline Forensic Correlation Engine.  
Its sole job is to ingest raw CSV output from tools like MemProcFS, normalise it,
and produce typed, analysis-ready CSV files — all without any external database.

### Core Philosophy

> **"CSV is the Source of Truth."**

Every piece of evidence enters the pipeline as a CSV and leaves as a CSV.  
No SQLite, no Parquet, no intermediate binary blobs.

---

## The Lossless Rule

**Zero data loss is allowed — ever.**

| Principle | Detail |
|-----------|--------|
| No dropped rows | If a CSV line is malformed, it is captured verbatim and logged to `_ingest_errors.csv`. It is **never** silently discarded. |
| No type coercion on read | Every value is ingested as a Python `str`. Type conversion happens only during the explicit Parsing phase. |
| Encoding resilience | Attempt `utf-8-sig` first, fall back to `latin-1`. Never crash on encoding errors. |
| Integrity tracking | SHA-256 hash and row count are recorded at load time for every input file. |

---

## Directory Structure

```
MemFlow/                         # Project root
│
├── memflow_common/              # Shared I/O, logging, safe CSV handling
│   ├── __init__.py
│   └── csv_io.py                # RawTable, read_csv_safe, write_csv_safe
│
├── memflow_parser/              # Engine: Raw CSV → Typed CSV (via Specs)
│   └── __init__.py
│
├── memflow_specs/               # Machine-readable YAML table definitions
│   └── __init__.py
│
├── tools/                       # Standalone entry-point scripts
│   └── __init__.py
│
├── docs/                        # Project documentation
│   ├── 00_context.md            # ← You are here
│   └── 05_cli_contract.md       # Standard CLI arguments for every tool
│
├── tests/                       # Unit and integration tests
│   └── __init__.py
│
├── requirements.txt             # Python dependencies (pinned)
└── README.md                    # Quick-start guide
```

---

## Data-Flow Summary

```
Raw CSVs (MemProcFS)
       │
       ▼
  ┌──────────┐
  │ Ingestion │  read_csv_safe()  →  RawTable (all strings)
  └──────────┘
       │
       ▼
  ┌───────────┐
  │ Inventory  │  Scan <case>/csv/ to discover what tables exist
  └───────────┘
       │
       ▼
  ┌──────────┐
  │  Parsing  │  Apply YAML Spec → Typed CSV (dates, ints, etc.)
  └──────────┘
       │
       ▼
  <case>/csv/          Typed output CSVs
  <case>/artifacts/    Reports, timelines, correlation results
```

---

## Runtime Outputs

All tools write their results under the `--case` directory:

| Path | Purpose |
|------|---------|
| `<case>/csv/` | Typed CSV output files |
| `<case>/artifacts/` | Reports, timelines, HTML summaries |
| `<case>/logs/` | Per-run log files |

---

*Document version: 1.0 — Phase 1 Foundation*

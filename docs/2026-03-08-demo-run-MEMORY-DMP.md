# MemFlow Demo Run - MEMORY.DMP

**Date:** 2026-03-08  
**Dump:** `C:\WorkProjects\MemFlow\MEMORY.DMP` (4.0 GB, Windows 10.0.26200 x64)  
**Case:** `case_demo/`

## Pipeline Execution

| Step | Tool | Duration | Result |
|------|------|----------|--------|
| 1. Ingest | `run_extract.py` (MemProcFS API + async forensic) | ~60s | 134 processes, 59 connections, 25 forensic CSVs |
| 2. Inventory | `memflow_inventory` | ~12s | 25 files cataloged, JSON + manifest written |
| 3. Scaffold | `memflow_spec_scaffold` | ~3s | 25 YAML specs generated |
| 4. Parse | `memflow_parse_generic` | ~21s | 25 typed CSVs, 0 conversion errors |
| 5a. Alerts - Process | `memflow_alerts_process` | ~4s | **2 alerts** |
| 5b. Alerts - Network | `memflow_alerts_network` | ~3s | **1 alert** |
| 5c. Alerts - Injection | `memflow_alerts_injection` | ~4s | **1 alert** |
| 5d. Alerts - Persistence | `memflow_alerts_persistence` | ~4s | 0 alerts |
| 5e. Alerts - Lateral | `memflow_alerts_lateral` | ~4s | 0 alerts |

**Total pipeline: ~115 seconds end-to-end.**

## Alerts Summary (4 total)

### HIGH - PARENT_CHILD_MISMATCH (2x)
- `csrss.exe` (PID 664) parent is `svchost.exe` (PID 648) instead of expected `smss.exe`
- `winlogon.exe` (PID 724) parent is `svchost.exe` (PID 648) instead of expected `smss.exe`

### HIGH - LISTENER_TRAP (1x)
- `OneDrive.Sync.Service.exe` (PID 4528) LISTENING on port 42050, not in approved server list

### HIGH - REFLECTIVE_DLL (1x)
- PID 8424 (`backgroundTaskHost.exe`) has MZ header at 0xe83428a000 with no backing file (PEB_BAD_LDR in FindEvil)

## Data Extracted

| CSV | Rows |
|-----|------|
| process.csv | 138 |
| net.csv | 59 |
| findevil.csv | 36 |
| modules.csv | 7,120 |
| handles.csv | 51,435 |
| files.csv | 21,384 |
| threads.csv | 1,505 |
| tasks.csv | 201 |
| timeline_all.csv | 784,397 |
| drivers.csv | 151 |
| devices.csv | 471 |
| unloaded_modules.csv | 339 |

## Notes

- MemProcFS Python API init with `-forensic 1` blocks; workaround: init without forensic, then enable via VFS write (`/forensic/forensic_enable.txt`)
- Dokan driver not installed; MemProcFS.exe fallback mount cannot work without it
- `services.csv`, `netdns.csv`, `prefetch.csv`, `yara.csv` extracted but had 0 data rows
- `typed_registry.csv` not available (MemProcFS forensic scan does not produce standalone registry CSV; data is in `timeline_registry.csv`)
- Persistence alerting limited: no registry Run key data, no service data, tasks table missing expected `action` column

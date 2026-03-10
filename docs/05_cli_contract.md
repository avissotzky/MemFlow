# MemFlow – CLI Contract (MF-001)

## Purpose

Every tool in the `tools/` directory **must** follow the same CLI argument
contract so that scripts can be chained, automated, and reasoned about
uniformly.

---

## Standard Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--case` | `-c` | **Yes** | — | Absolute or relative path to the investigation root directory. All output is written under this path. |
| `--in` | `-i` | **Yes** | — | Path to the input file **or** directory to process. |
| `--out` | `-o` | No | `<case>/csv/` | Path to the output directory. Created automatically if it does not exist. |
| `--log-level` | `-l` | No | `INFO` | Logging verbosity. One of: `DEBUG`, `INFO`, `WARN`, `ERROR`. |

### Rules

1. **`--case` is the anchor.**  
   If `--out` is omitted, output defaults to `<case>/csv/`.  
   Log files are always written to `<case>/logs/`.

2. **`--in` may be a file or a directory.**  
   When it is a directory, the tool should process every supported file inside
   it (non-recursive unless the tool documents otherwise).

3. **`--out` is always a directory, never a file.**  
   The tool decides the output filename(s) within that directory.

4. **`--log-level` controls console and file output equally.**  
   At `DEBUG`, every CSV row-level operation is logged.  
   At `INFO`, only summaries (file opened, rows processed, errors) are logged.  
   At `WARN` / `ERROR`, only problems are logged.

---

## Example Invocation

```bash
python -m tools.ingest_csv \
    --case  C:\Cases\IR-2025-042 \
    --in    C:\Cases\IR-2025-042\raw\proc.csv \
    --out   C:\Cases\IR-2025-042\csv \
    --log-level DEBUG
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Success — all rows processed (warnings may exist). |
| `1`  | Partial failure — some rows written to `_ingest_errors.csv`. |
| `2`  | Fatal — input not found, unreadable, or output dir cannot be created. |

---

## Argparse Template

Every tool should use a shared argument builder so the interface is
identical. The canonical helper lives in `memflow_common/cli.py` (to be
created in a future ticket) and exposes:

```python
from memflow_common.cli import build_arg_parser

def main():
    parser = build_arg_parser(description="Ingest raw CSV into typed CSV.")
    args = parser.parse_args()
    # args.case, args.in_path, args.out, args.log_level
```

Until that helper exists, every tool must manually replicate the four
arguments above using `argparse`.

---

## Validation on Startup

Before any processing begins, every tool **must**:

1. Verify `--case` exists (or create it with a warning).
2. Verify `--in` exists and is readable.
3. Verify/create `--out` directory.
4. Configure logging to both console and `<case>/logs/<tool>_<timestamp>.log`.

---

*Document version: 1.0 — Phase 1 Foundation*

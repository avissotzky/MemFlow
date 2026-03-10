# MemFlow — מדריך משתמש מלא

> **"CSV הוא מקור האמת."**

---

## תוכן עניינים

1. [מה זה MemFlow?](#1-מה-זה-memflow)
2. [התקנה](#2-התקנה)
3. [ארכיטקטורת הפרויקט](#3-ארכיטקטורת-הפרויקט)
4. [צינור העיבוד (Pipeline)](#4-צינור-העיבוד-pipeline)
5. [חוזה ה-CLI — ארגומנטים סטנדרטיים](#5-חוזה-ה-cli--ארגומנטים-סטנדרטיים)
6. [מדריך כלים מפורט](#6-מדריך-כלים-מפורט)
   - 6.0 [memflow-extract — חילוץ מבוסס תוספים](#60-memflow-extract--חילוץ-מבוסס-תוספים)
   - 6.1 [memflow-ingest — חילוץ מ-Memory Dump](#61-memflow-ingest--חילוץ-מ-memory-dump-mf-010--mf-015)
   - 6.2 [memflow-inventory — סריקת CSV ובדיקת תקינות](#62-memflow-inventory--סריקת-csv-ובדיקת-תקינות-mf-020)
   - 6.3 [memflow-spec-scaffold — יצירת מפרטי YAML](#63-memflow-spec-scaffold--יצירת-מפרטי-yaml-mf-030)
   - 6.4 [memflow-parse-generic — המרה מ-Raw ל-Typed CSV](#64-memflow-parse-generic--המרה-מ-raw-ל-typed-csv-mf-050)
   - 6.5 [memflow-validate — אימות שלמות נתונים](#65-memflow-validate--אימות-שלמות-נתונים-mf-070)
   - 6.6 [memflow-entropy — ניתוח אנטרופיה וגיבובים](#66-memflow-entropy--ניתוח-אנטרופיה-וגיבובים-mf-080)
   - 6.7 [memflow-alerts-network — זיהוי חריגות רשת](#67-memflow-alerts-network--זיהוי-חריגות-רשת-mf-101)
   - 6.8 [memflow-alerts-injection — זיהוי הזרקת קוד](#68-memflow-alerts-injection--זיהוי-הזרקת-קוד-mf-102)
   - 6.9 [memflow-alerts-process — זיהוי תהליכים חשודים](#69-memflow-alerts-process--זיהוי-תהליכים-חשודים-mf-103)
   - 6.10 [memflow-alerts-persistence — זיהוי מנגנוני התמדה](#610-memflow-alerts-persistence--זיהוי-מנגנוני-התמדה-mf-104)
   - 6.11 [memflow-alerts-lateral — זיהוי תנועה רוחבית](#611-memflow-alerts-lateral--זיהוי-תנועה-רוחבית-mf-105)
7. [ספריות משותפות](#7-ספריות-משותפות)
   - 7.1 [memflow_common — קריאה וכתיבה בטוחה של CSV](#71-memflow_common--קריאה-וכתיבה-בטוחה-של-csv)
   - 7.2 [memflow_parser — מנוע המרת טיפוסים](#72-memflow_parser--מנוע-המרת-טיפוסים)
8. [תהליך עבודה מלא — דוגמה מקצה לקצה](#8-תהליך-עבודה-מלא--דוגמה-מקצה-לקצה)
9. [מבנה תיקיות — מדריך מלא](#9-מבנה-תיקיות--מדריך-מלא)
10. [טבלת קודי יציאה](#10-טבלת-קודי-יציאה)
11. [פתרון בעיות](#11-פתרון-בעיות)

---

## 1. מה זה MemFlow?

MemFlow הוא **מנוע קורלציה פורנזי לא-מקוון** (Offline Forensic Correlation Engine). הכלי לוקח פלט CSV גולמי מכלי פורנזיקת זיכרון — בעיקר **MemProcFS** — וממיר אותו לקבצי CSV מנורמלים, מוקלדים ומוכנים לניתוח. לאחר מכן הוא מריץ סדרת גלאי התראות אבטחה על הנתונים.

**עקרונות מפתח:**

- **CSV הוא פורמט הנתונים היחיד** — ללא SQLite, ללא Parquet, ללא blobs בינאריים.
- **אפס איבוד נתונים** — כל שורה נשמרת; שורות פגומות נרשמות ביומן, לעולם לא נמחקות.
- **עבודה לא-מקוונת לחלוטין** — אין צורך באינטרנט. אין מסדי נתונים חיצוניים. Python 3.10+ בלבד.
- **סקריפטים עצמאיים** — כל כלי הוא נקודת כניסה עצמאית עם ממשק CLI אחיד.

---

## 2. התקנה

### 2.1 דרישות מקדימות

- **Python 3.10** ומעלה
- **pip** (מגיע עם Python)
- קובץ Memory Dump (`.raw`, `.dmp`, `.vmem` וכו') לשלב החילוץ

### 2.2 התקנה רגילה

```bash
# כנסו לתיקיית הפרויקט
cd MemFlow

# צרו סביבה וירטואלית
python -m venv .venv

# הפעלה (Windows)
.venv\Scripts\activate

# הפעלה (Linux / macOS)
# source .venv/bin/activate

# התקנת MemFlow וכל התלויות
pip install .
```

### 2.3 התקנה במכונה מנותקת מרשת (Air-Gapped)

במכונה **עם** גישה לאינטרנט:

```bash
# הורדת כל התלויות כקבצי wheel
pip download . -d ./offline_packages
```

העבירו את כל תיקיית הפרויקט (כולל `offline_packages/`) למכונת היעד.

במכונה **המנותקת**:

```bash
cd MemFlow
python -m venv .venv
.venv\Scripts\activate
pip install --no-index --find-links=./offline_packages .
```

### 2.4 אימות ההתקנה

לאחר ההתקנה, כל הכלים זמינים כפקודות:

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

### 2.5 התקנת תלויות בדיקה

```bash
pip install ".[test]"
python -m pytest tests/ -v
```

---

## 3. ארכיטקטורת הפרויקט

```
MemFlow/
├── extractors/              # תוספי חילוץ (קובץ אחד לכל יכולת)
│   ├── __init__.py          # גילוי אוטומטי של תוספים
│   ├── base.py              # BaseExtractor ABC + ExtractResult + עזרים משותפים
│   ├── processes.py         # רשימת תהליכים (API)
│   ├── dlls.py              # DLLs טעונים לכל תהליך (API)
│   ├── netstat.py           # חיבורי רשת (VFS)
│   ├── modules.py           # מודולי kernel (forensic CSV)
│   ├── handles.py           # טבלת handles (forensic CSV)
│   ├── files.py             # קבצים פתוחים (forensic CSV)
│   ├── threads.py           # threads (forensic CSV)
│   ├── tasks.py             # משימות מתוזמנות (forensic CSV)
│   ├── drivers.py           # דרייברים (forensic CSV)
│   ├── devices.py           # התקנים (forensic CSV)
│   ├── unloaded_modules.py  # מודולים שנפרקו (forensic CSV)
│   ├── findevil.py          # תוצאות FindEvil (forensic CSV)
│   ├── services.py          # שירותי Windows (forensic CSV)
│   └── timelines.py         # כל קבצי timeline_*.csv כולל timeline_registry.csv (forensic CSV)
│
├── memflow_common/          # I/O משותף, לוגים, טיפול בטוח ב-CSV
│   ├── __init__.py
│   └── csv_io.py            # RawTable, read_csv_safe, write_csv_safe
│
├── memflow_parser/          # מנוע: Raw CSV → Typed CSV (דרך מפרטי YAML)
│   ├── __init__.py
│   └── engine.py            # load_spec, parse_table, convert_value
│
├── memflow_specs/           # הגדרות YAML לטבלאות (machine-readable)
│   └── __init__.py          # (קבצי YAML נוצרים ע"י spec-scaffold)
│
├── tools/                   # סקריפטי כניסה עצמאיים (11 כלים)
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
├── run_extract.py           # אורכסטרטור תוספים (מריץ כל/חלק מהחילוצים)
├── tests/                   # בדיקות יחידה ואינטגרציה (192 בדיקות)
├── docs/                    # תיעוד
├── pyproject.toml           # הגדרות חבילה
├── requirements.txt         # רשימת תלויות (legacy)
└── README.md
```

### תפקידי חבילות

| חבילה | תפקיד |
|-------|--------|
| `extractors` | תוספי חילוץ מבוססי plugin — קובץ אחד לכל יכולת של MemProcFS, מתגלה אוטומטית ע"י האורכסטרטור |
| `memflow_common` | קריאה/כתיבה משותפת של CSV עם אחריות לשלמות, חוסן קידוד, ומעקב SHA-256 |
| `memflow_parser` | מנוע המרת טיפוסים — ממיר ערכי מחרוזת ל-int, float, bool, timestamp, hex_int |
| `memflow_specs` | מאחסן קבצי מפרט YAML שמגדירים טיפוסי עמודות לכל טבלה |
| `tools` | 11 כלים עצמאיים בשורת הפקודה — נקודות הכניסה למשתמש |

---

## 4. צינור העיבוד (Pipeline)

MemFlow עוקב אחר צינור עיבוד סדרתי קפדני. כל שלב מזין את הבא:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        צינור העיבוד של MemFlow                         │
└─────────────────────────────────────────────────────────────────────────┘

  Memory Dump (.raw / .dmp)
         │
         ▼
  ┌──────────────┐
  │  1. חילוץ    │  memflow-ingest
  │   INGEST     │  חילוץ קבצי CSV גולמיים מ-MemProcFS
  └──────────────┘
         │  פלט: <case>/csv/*.csv (גולמי)
         ▼
  ┌──────────────┐
  │  2. מלאי     │  memflow-inventory
  │  INVENTORY   │  סריקת CSVs, זיהוי חריגות, יצירת מניפסט
  └──────────────┘
         │  פלט: JSON מלאי + מניפסט CSV
         ▼
  ┌──────────────┐
  │  3. שלדים    │  memflow-spec-scaffold
  │  SCAFFOLD    │  יצירת מפרטי YAML מהמלאי
  └──────────────┘
         │  פלט: memflow_specs/*.yaml
         ▼
  ┌──────────────┐
  │  4. ניתוח    │  memflow-parse-generic
  │   PARSE      │  החלת מפרטים → המרה מ-Raw CSV ל-Typed CSV
  └──────────────┘
         │  פלט: <case>/csv/typed_*.csv
         ▼
  ┌──────────────┐
  │  5. אימות    │  memflow-validate
  │  VALIDATE    │  בדיקת שוויון שורות, אילוצים, יחסים בין טבלאות
  └──────────────┘
         │  פלט: validation_report.md
         ▼
  ┌────────────────────────────────────────────────┐
  │            6. כלי ניתוח והתראות                 │
  │                                                │
  │  memflow-entropy          אנטרופיה + גיבובים   │
  │  memflow-alerts-network   חריגות רשת            │
  │  memflow-alerts-injection הזרקת קוד             │
  │  memflow-alerts-process   תהליכים חשודים        │
  │  memflow-alerts-persist.  מנגנוני התמדה         │
  │  memflow-alerts-lateral   תנועה רוחבית          │
  └────────────────────────────────────────────────┘
         │  פלט: <case>/csv/alerts_*.csv, file_entropy.csv
         ▼
     ממצאים מוכנים לניתוח
```

---

## 5. חוזה ה-CLI — ארגומנטים סטנדרטיים

כל הכלים עוקבים אחר אותו חוזה CLI ליצירת עקביות ואפשרות אוטומציה.

### ארגומנטים סטנדרטיים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | נתיב מוחלט או יחסי לתיקיית שורש החקירה. כל הפלט נכתב תחת נתיב זה. |
| `--in` | `-i` | משתנה | — | נתיב לקובץ קלט **או** תיקייה לעיבוד. |
| `--out` | `-o` | לא | `<case>/csv/` | נתיב לתיקיית הפלט. נוצרת אוטומטית אם לא קיימת. |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור: `DEBUG`, `INFO`, `WARN`, `ERROR`. |

### כללים

1. **`--case` הוא העוגן.** אם `--out` לא צוין, הפלט ילך ל-`<case>/csv/`. קבצי לוג תמיד ב-`<case>/logs/`.
2. **`--in` יכול להיות קובץ או תיקייה.** כשזו תיקייה, הכלי מעבד כל קובץ נתמך בתוכה.
3. **`--out` הוא תמיד תיקייה, לעולם לא קובץ.** הכלי מחליט על שמות קבצי הפלט.
4. **`--log-level` שולט גם בקונסול וגם בקובץ הלוג.** ב-`DEBUG`, כל פעולה ברמת שורה נרשמת. ב-`INFO`, רק סיכומים.

### קודי יציאה סטנדרטיים

| קוד | משמעות |
|-----|--------|
| `0` | הצלחה — כל הפעולות הושלמו ללא בעיות. |
| `1` | כשלון חלקי — נוצר פלט, אך עם אזהרות/שגיאות. |
| `2` | קריטי — לא ניתן להמשיך (קלט חסר, תלות חסרה). |

---

## 6. מדריך כלים מפורט

---

### 6.0 memflow-extract — חילוץ מבוסס תוספים

**מטרה:** חילוץ סוגי נתונים ספציפיים מ-Memory Dump באמצעות ארכיטקטורת תוספים (plugin). כל יכולת חילוץ (תהליכים, DLLs, threads, רשת וכו') היא תוסף עצמאי. האורכסטרטור פותח סשן VMM יחיד ומריץ את כל (או חלק מ) התוספים.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--dump` | `-d` | **כן** | — | נתיב לקובץ ה-Memory Dump |
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט ל-CSVs |
| `--only` | — | לא | — | רשימה מופרדת בפסיקים של חילוצים להרצה (למשל `processes,dlls,netstat`) |
| `--exclude` | — | לא | — | רשימה מופרדת בפסיקים של חילוצים לדלג עליהם (למשל `timelines`) |
| `--timeout` | `-t` | לא | `300` | שניות להמתנה ליצירת CSVs פורנזיים |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |
| `--list` | — | לא | — | הצגת כל התוספים הזמינים ויציאה |

#### תוספים זמינים

| שם | מקור | פלט | תיאור |
|----|------|-----|--------|
| `processes` | API | `process.csv` | רשימת תהליכים (PID, PPID, שם, נתיב, cmdline, SID, username, state, זמנים, wow64) |
| `dlls` | API | `dlls.csv` | DLLs טעונים לכל תהליך (שם מודול, נתיב, בסיס, גודל, כניסה, is_wow64, module_type, חותמות PE) |
| `netstat` | VFS | `net.csv` | חיבורי רשת (pid, process_name, פרוטוקול, כתובות, פורטים, מצב) |
| `modules` | Forensic CSV | `modules.csv` | מודולי kernel כלל-מערכתיים |
| `handles` | Forensic CSV | `handles.csv` | טבלת handles |
| `files` | Forensic CSV | `files.csv` | קבצים פתוחים |
| `threads` | Forensic CSV | `threads.csv` | מידע על threads |
| `tasks` | Forensic CSV | `tasks.csv` | משימות מתוזמנות |
| `drivers` | Forensic CSV | `drivers.csv` | דרייברי kernel |
| `devices` | Forensic CSV | `devices.csv` | אובייקטי התקנים |
| `unloaded_modules` | Forensic CSV | `unloaded_modules.csv` | מודולים שנפרקו |
| `findevil` | Forensic CSV | `findevil.csv` | תוצאות סריקת FindEvil |
| `services` | Forensic CSV | `services.csv` | שירותי Windows |
| `timelines` | Forensic CSV | `timeline_*.csv` | כל קבצי ציר הזמן כולל timeline_registry.csv |

#### אסטרטגיות מקור

| מקור | איך זה עובד |
|------|-------------|
| **API** | גישה ישירה ל-API של MemProcFS (למשל `vmm.process_list()`, `proc.module_list()`). לא דורש מצב פורנזי. |
| **VFS** | קורא ומנתח קובץ טקסט ממערכת הקבצים הוירטואלית (למשל `/sys/net/netstat.txt`). |
| **Forensic CSV** | מעתיק CSVs מוכנים מ-`/forensic/csv/`. דורש מצב פורנזי (מופעל אוטומטית). |

#### דוגמאות

**הצגת תוספים זמינים:**

```bash
python run_extract.py --list
```

**הרצת כל התוספים:**

```bash
python run_extract.py \
    --dump C:\Evidence\memory.raw \
    --case C:\Cases\IR-2025-042
```

**הרצת תוספים ספציפיים בלבד:**

```bash
python run_extract.py \
    --dump C:\Evidence\memory.raw \
    --case C:\Cases\IR-2025-042 \
    --only processes,dlls,netstat
```

**דילוג על קבצי timeline גדולים:**

```bash
python run_extract.py \
    --dump C:\Evidence\memory.raw \
    --case C:\Cases\IR-2025-042 \
    --exclude timelines
```

#### הוספת תוסף חדש

צרו קובץ יחיד ב-`extractors/`, למשל `extractors/vads.py`:

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
            # ... ספירת VADs ...
            pass
        self.write_csv(out_dir, self.output_filename, headers, rows)
        return ExtractResult(ok=True, rows=len(rows), files_written=["vads.csv"])
```

האורכסטרטור מגלה אותו אוטומטית בהרצה הבאה. אין צורך ברישום או שינוי הגדרות.

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | כל התוספים שנבחרו הצליחו |
| `1` | חלק מהתוספים נכשלו (הצלחה חלקית) |
| `2` | קריטי: memprocfs חסר, קובץ dump לא נמצא, או לא נבחרו תוספים |

---

### 6.1 memflow-ingest — חילוץ מ-Memory Dump (MF-010 / MF-015)

**מטרה:** חילוץ קבצי CSV גולמיים מתוך Memory Dump באמצעות MemProcFS. זוהי נקודת הכניסה של כל הצינור.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--device` | `-d` | **כן** | — | נתיב לקובץ ה-Memory Dump (`.raw`, `.dmp`, `.vmem`) |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט ל-CSVs שחולצו |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |
| `--wait` | `-w` | לא | `15` | מקסימום שניות להמתנה ל-MemProcFS לאכלוס CSVs |
| `--full-dump` | — | לא | `False` | חילוץ עמוק של ארטיפקטים (MF-015) |

> **הערה:** כלי זה משתמש ב-`--device` במקום `--in` כי הקלט הוא Memory Dump, לא CSV.

#### איך זה עובד

1. **בדיקת תלויות** — מוודא שחבילת `memprocfs` מותקנת. יוצא עם קוד 2 אם חסרה.
2. **אתחול MemProcFS** — מפעיל את MemProcFS עם הדגלים: `-device <path>`, `-forensic 1`, `-forensic-scan-ranges 1`, `-csv`.
3. **המתנה למוכנות** — בודק את מערכת הקבצים הוירטואלית כל 2 שניות עד שתיקיית ה-CSV (`/forensic/csv/`) מופיעה, עד `--wait` שניות.
4. **חילוץ CSVs** — מעתיק כל קובץ `.csv` מה-VFS לתיקיית הפלט, קורא בנתחים של 1 MiB.
5. **חילוץ עמוק** (אם `--full-dump`) — מחלץ ארטיפקטים פורנזיים נוספים (ראו להלן).

#### חילוץ עמוק (--full-dump)

כאשר `--full-dump` מופעל, הכלי מבצע ארבעה שלבי חילוץ נוספים:

| שלב | מה מחולץ | נתיב פלט |
|-----|----------|----------|
| רגיסטרי | SYSTEM, SOFTWARE, SAM, SECURITY, וכל קבצי NTUSER.DAT | `<case>/raw/registry/` |
| ניתוח FindEvil | ניתוח דוח FindEvil למציאת PIDs המסומנים כ-CRITICAL, HIGH, MALICIOUS, או ALERT | `<case>/docs/findevil_raw.txt` |
| בינאריים חשודים | Minidumps וקבצים פתוחים עבור PIDs מסומנים + LSASS | `<case>/raw/dumps/`, `<case>/raw/files/` |
| קבצים משוחזרים | קבצים חצובים: `.exe`, `.dll`, `.ps1`, `.bat`, `.sys` | `<case>/raw/recovered_files/` |

> **אזהרה:** חילוץ עמוק יכול לצרוך שטח דיסק של בערך **פי 2 מגודל תמונת ה-RAM**.

#### קבועים חשובים

| קבוע | ערך | תיאור |
|------|-----|--------|
| `VFS_CSV_PATH` | `/forensic/csv/` | נתיב CSVs ב-VFS |
| `READ_CHUNK_SIZE` | 1 MiB | גודל נתח קריאה |
| `POLL_INTERVAL_SECONDS` | 2 | מרווח בדיקה בשניות |
| `REGISTRY_HIVES` | SYSTEM, SOFTWARE, SAM, SECURITY | רגיסטרי לחילוץ |
| `RECOVERED_EXTENSIONS` | .exe, .dll, .ps1, .bat, .sys | סיומות לשחזור |

#### דוגמאות

**חילוץ בסיסי:**

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device C:\Evidence\memory.raw
```

זה יבצע:
- יצירת `C:\Cases\IR-2025-042\` אם לא קיימת
- חילוץ כל ה-CSVs ל-`C:\Cases\IR-2025-042\csv\`
- כתיבת לוגים ל-`C:\Cases\IR-2025-042\logs\`

**עם תיקיית פלט מותאמת והמתנה מוארכת:**

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device D:\Evidence\server_mem.dmp \
    --out C:\Cases\IR-2025-042\raw_csv \
    --wait 60 \
    --log-level DEBUG
```

**חילוץ פורנזי מלא:**

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device C:\Evidence\memory.raw \
    --full-dump
```

לאחר הרצה זו, תיקיית החקירה תכיל:

```
C:\Cases\IR-2025-042\
├── csv\                     # כל ה-CSVs הפורנזיים
│   ├── process.csv
│   ├── net.csv
│   ├── registry.csv
│   └── ... (כל ה-CSVs של MemProcFS)
├── raw\
│   ├── registry\            # קבצי רגיסטרי
│   │   ├── SYSTEM
│   │   ├── SOFTWARE
│   │   ├── SAM
│   │   └── SECURITY
│   ├── dumps\               # Minidumps של תהליכים
│   │   ├── PID_1234\
│   │   └── PID_4567\
│   ├── files\               # קבצים פתוחים לפי PID
│   └── recovered_files\     # קבצים משוחזרים
├── docs\
│   └── findevil_raw.txt     # דוח FindEvil
└── logs\
    └── ingest_<timestamp>.log
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | כל ה-CSVs חולצו בהצלחה |
| `1` | חלק מהחילוצים נכשלו (הצלחה חלקית) |
| `2` | קריטי: `memprocfs` לא מותקן, קובץ device לא נמצא, או תיקיית CSV לא הופיעה |

---

### 6.2 memflow-inventory — סריקת CSV ובדיקת תקינות (MF-020)

**מטרה:** סריקת תיקייה של קבצי CSV, בניית מלאי מלא של כל טבלה, וזיהוי חריגות (קבצים ריקים, כותרות כפולות, שגיאות קריאה).

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה לסריקה |
| `--out` | `-o` | לא | `<case>` | תיקיית פלט בסיסית |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### איך זה עובד

1. סורק את תיקיית הקלט לכל קבצי `*.csv`.
2. לכל קובץ, קורא אותו באמצעות `read_csv_safe()` ורושם:
   - שם קובץ, נתיב מלא
   - כותרות עמודות
   - ספירת שורות
   - גיבוב SHA-256
   - חריגות שנמצאו
3. מייצר מלאי JSON ומניפסט CSV שטוח.

#### זיהוי חריגות

המלאי מסמן אוטומטית את הבעיות הבאות:

| חריגה | תיאור |
|-------|--------|
| `empty_file` | לקובץ אין שורת כותרת כלל (0 בתים או רק רווחים) |
| `empty_data` | לקובץ יש כותרות אבל אפס שורות נתונים |
| `duplicate_header: <X>` | כותרת העמודה `X` מופיעה יותר מפעם אחת |
| `read_error: <msg>` | הקובץ לא ניתן לניתוח (פגום, בעיית קידוד) |
| `locked_by_os` | הקובץ העלה שגיאת `PermissionError` (נעול ע"י תהליך אחר) |

#### דוגמאות

**מלאי בסיסי לאחר חילוץ:**

```bash
memflow-inventory \
    --case C:\Cases\IR-2025-042
```

זה סורק את `C:\Cases\IR-2025-042\csv\` ומייצר:
- `C:\Cases\IR-2025-042\docs\03_csv_inventory.json`
- `C:\Cases\IR-2025-042\artifacts\_inventory_manifest.csv`

**תיקיית קלט מותאמת:**

```bash
memflow-inventory \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\raw_csv \
    --log-level DEBUG
```

**בדיקת המניפסט:**

קובץ `_inventory_manifest.csv` מכיל שורה אחת לכל קובץ CSV:

```csv
"file","row_count","columns","sha256","anomalies"
"process.csv","1842","pid,ppid,name,path,cmdline,user","a1b2c3...","none"
"net.csv","523","pid,protocol,local_addr,local_port,remote_addr,remote_port,state","d4e5f6...","none"
"empty_table.csv","0","col_a,col_b","789abc...","empty_data"
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | כל ה-CSVs נסרקו, לא נמצאו חריגות |
| `1` | נמצאה לפחות חריגה אחת |
| `2` | קריטי: תיקיית הסריקה לא קיימת |

---

### 6.3 memflow-spec-scaffold — יצירת מפרטי YAML (MF-030)

**מטרה:** יצירה אוטומטית של קבצי מפרט YAML לכל טבלה שנמצאה במלאי. מפרטים אלו מגדירים טיפוסי עמודות ומשמשים את הפרסר.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/docs/03_csv_inventory.json` | נתיב ל-JSON המלאי |
| `--out` | `-o` | לא | `memflow_specs/` | תיקיית פלט למפרטי YAML |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |
| `--overwrite` | — | לא | `False` | דריסת קבצי מפרט קיימים |

#### איך זה עובד

1. קורא את JSON המלאי שנוצר ע"י `memflow-inventory`.
2. לכל טבלה במלאי:
   - יוצר קובץ YAML בשם `<table_name>.yaml`.
   - כל עמודה מוגדרת כברירת מחדל כ-`type: "raw"` (העברה ישירה, ללא המרה).
   - אם מפרט כבר קיים, הוא **מדולג** (אלא אם `--overwrite` מופעל).
3. טבלאות ללא כותרות מדולגות.

#### פורמט YAML שנוצר

עבור טבלה `process.csv` עם כותרות `pid, ppid, name, path`:

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

#### עריכת מפרטים לאחר יצירה

לאחר ה-scaffold, **עליכם לערוך ידנית את המפרטים** ולהקצות טיפוסים נכונים. הטיפוסים הנתמכים הם:

| טיפוס | תיאור | דוגמת קלט | דוגמת פלט |
|-------|--------|-----------|----------|
| `raw` | ללא המרה (העברה ישירה) | `"hello"` | `"hello"` |
| `string` | זהה ל-raw | `"hello"` | `"hello"` |
| `int` | מספר שלם עשרוני | `"1234"` | `"1234"` (מאומת) |
| `hex_int` | הקסדצימלי → עשרוני | `"0xFF"` | `"255"` |
| `float` | מספר עשרוני צף | `"3.14"` | `"3.14"` (מאומת) |
| `bool` | בוליאני | `"true"`, `"yes"`, `"1"` | `"True"` |
| `timestamp` | תאריך/שעה → ISO 8601 | `"2025/01/15 08:30:00"` | `"2025-01-15T08:30:00"` |

**דוגמה למפרט שנערך ידנית:**

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

#### דוגמאות

**יצירת מפרטים מהמלאי:**

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042
```

**דריסת מפרטים קיימים:**

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042 \
    --overwrite
```

**תיקיית פלט מותאמת:**

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042 \
    --out C:\Cases\IR-2025-042\specs
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | מפרטים נוצרו בהצלחה |
| `2` | קריטי: JSON המלאי לא נמצא או לא קריא |

---

### 6.4 memflow-parse-generic — המרה מ-Raw ל-Typed CSV (MF-050)

**מטרה:** החלת מפרטי YAML על קבצי CSV גולמיים, המרת ערכי מחרוזת לטיפוסים הנכונים (int, float, timestamp וכו') ויצירת קבצי CSV מוקלדים.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | **כן** | — | נתיב לקובץ CSV גולמי **או** תיקייה של CSVs |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט ל-CSVs מוקלדים |
| `--specs` | `-s` | לא | `memflow_specs/` | תיקייה המכילה מפרטי YAML |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### איך זה עובד

1. אוסף רשימת קבצי CSV לעיבוד (קובץ בודד או כל `*.csv` בתיקייה).
2. לכל CSV:
   - מחפש מפרט מתאים: `process.csv` → `process.yaml`.
   - קורא את ה-CSV הגולמי באמצעות `read_csv_safe()`.
   - מחיל המרות טיפוסים עמודה-עמודה.
   - אם ערך לא ניתן להמרה, **הערך הגולמי המקורי נשמר** ו-`ParseError` נרשם.
   - כותב את הפלט המוקלד ל-`typed_<table>.csv`.
   - מוסיף שגיאות המרה ל-`_parsing_errors.csv`.

#### הבטחת אפס-איבוד

**ספירת שורות הפלט תמיד שווה לספירת שורות הקלט.** אף שורה לא נמחקת לעולם. אם תא לא ניתן להמרה, הערך הגולמי נשמר והשגיאה נרשמת בנפרד.

#### התאמת מפרטים

הפרסר מתאים CSVs למפרטים לפי שם הגזע:

| קובץ CSV | מפרט צפוי |
|----------|----------|
| `process.csv` | `process.yaml` |
| `net.csv` | `net.yaml` |
| `registry.csv` | `registry.yaml` |
| `vad.csv` | `vad.yaml` |

אם לא נמצא מפרט מתאים, הקובץ **מדולג** עם קוד יציאה 2.

#### קבצי פלט

| קובץ | תיאור |
|------|--------|
| `typed_<table>.csv` | הגרסה המוקלדת של ה-CSV הגולמי |
| `_parsing_errors.csv` | שגיאות המרה מצטברות (מצב הוספה) |

ה-CSV של השגיאות מכיל את העמודות הבאות:

```csv
"source_file","row_index","column","raw_value","expected_type","error"
"process.csv","42","pid","not_a_number","int","invalid literal for int()"
```

#### דוגמאות

**ניתוח קובץ בודד:**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\process.csv
```

פלט: `C:\Cases\IR-2025-042\csv\typed_process.csv`

**ניתוח כל ה-CSVs בתיקייה:**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv
```

זה יעבד כל CSV שיש לו מפרט מתאים.

**תיקיית מפרטים מותאמת:**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv \
    --specs C:\Cases\IR-2025-042\custom_specs
```

**מצב Debug (רושם כל המרת שורה):**

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\process.csv \
    --log-level DEBUG
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | כל הקבצים נותחו ללא שגיאות המרה |
| `1` | לפחות קובץ אחד עם שגיאות המרה (שגיאות נרשמו, נתונים עדיין יוצרו) |
| `2` | קריטי: מפרט חסר, קובץ קלט חסר, או תיקיית מפרטים חסרה |

---

### 6.5 memflow-validate — אימות שלמות נתונים (MF-070)

**מטרה:** וידוא שה-CSVs המוקלדים עקביים ונכונים ע"י הרצת שלוש קטגוריות בדיקות: שוויון (parity), אילוצים (constraints), ויחסים בין טבלאות (relations).

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה עם קבצי `typed_*.csv` |
| `--out` | `-o` | לא | `<case>/artifacts/` | תיקיית פלט לדוח האימות |
| `--specs` | `-s` | לא | `memflow_specs/` | תיקיית מפרטי YAML |
| `--manifest` | `-m` | לא | `<case>/artifacts/_inventory_manifest.csv` | נתיב למניפסט המלאי |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### בדיקות אימות

**1. בדיקת שוויון (Parity Check)**

מוודאת שלכל CSV מוקלד יש אותה ספירת שורות כמו שדווח במניפסט המלאי. אם ל-`process.csv` היו 1842 שורות, גם ל-`typed_process.csv` חייבות להיות 1842 שורות.

**2. בדיקת אילוצים (Constraint Check)**

לכל CSV מוקלד עם מפרט מתאים, מוודאת שעמודות עם טיפוסים שאינם raw/string מכילות ערכים שאינם null. למשל, אם `pid` מוגדר כ-`type: "int"`, כל שורה חייבת להכיל ערך בעמודה זו.

**3. בדיקת יחסים (Relation Check)**

שלמות רפרנציאלית בין טבלאות. כרגע בודק:
- כל `pid` ב-`typed_net.csv` חייב להתקיים ב-`typed_process.csv`.

#### פלט — דוח אימות

הכלי מייצר דוח Markdown ב-`<out>/validation_report.md`:

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

#### דוגמאות

**אימות בסיסי:**

```bash
memflow-validate \
    --case C:\Cases\IR-2025-042
```

**מניפסט ומפרטים מותאמים:**

```bash
memflow-validate \
    --case C:\Cases\IR-2025-042 \
    --manifest C:\Cases\IR-2025-042\artifacts\_inventory_manifest.csv \
    --specs C:\Cases\IR-2025-042\specs
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | כל הבדיקות עוברות |
| `1` | לפחות בדיקה אחת נכשלה |
| `2` | קריטי: תיקיית typed או מניפסט לא נמצאו |

---

### 6.6 memflow-entropy — ניתוח אנטרופיה וגיבובים (MF-080)

**מטרה:** חישוב אנטרופיית Shannon, גיבובי MD5 ו-SHA-256 לקבצים שמופיעים ב-CSV. אנטרופיה גבוהה (קרובה ל-8.0) יכולה להצביע על בינאריים ארוזים, מוצפנים או דחוסים — נפוצים בתוכנות זדוניות.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | **כן** | — | נתיב ל-`files.csv` או `typed_files.csv` |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט |
| `--forensic-dir` | `-f` | לא | `<case>/forensic_files/` | תיקייה המכילה את הקבצים הפיזיים |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### איך זה עובד

1. קורא את ה-CSV ומזהה את עמודת נתיב הקובץ (מנסה: `file`, `filepath`, `path`, `name` וכו').
2. לכל שורה, מנסה לאתר את הקובץ:
   - קודם מנסה את הנתיב כפי שהוא (מוחלט).
   - אח"כ מנסה יחסית ל-`--forensic-dir`.
   - אח"כ מנסה רק את שם הקובץ ב-`--forensic-dir`.
3. קורא כל קובץ ומחשב:
   - **אנטרופיית Shannon** (סולם 0.0 – 8.0)
   - **גיבוב MD5**
   - **גיבוב SHA-256**
   - **גודל קובץ** בבתים
4. כותב תוצאות ל-`file_entropy.csv`.

#### הבנת ערכי אנטרופיה

| טווח אנטרופיה | פרשנות |
|---------------|--------|
| 0.0 – 1.0 | נמוכה מאוד — כנראה ריק או נתונים חוזרים |
| 1.0 – 4.0 | נמוכה — טקסט רגיל, נתונים פשוטים |
| 4.0 – 6.0 | בינונית — קבצי הרצה טיפוסיים, מסמכים |
| 6.0 – 7.0 | גבוהה — קוד מקומפל, דחיסה מסוימת |
| 7.0 – 7.99 | גבוהה מאוד — ארוז, מוצפן או דחוס (חשוד) |
| 8.0 | מקסימום — נתונים אקראיים לחלוטין (הצפנה חזקה או אריזה) |

#### עמודות פלט

```csv
"file_path","file_id","entropy","md5","sha256","file_size","status"
"C:\Windows\System32\svchost.exe","12","5.42","abc123...","def456...","51200","ok"
"C:\Temp\payload.bin","","7.98","789abc...","012def...","32768","ok"
"C:\missing.dll","15","","","","","not_found"
```

| עמודה | תיאור |
|-------|--------|
| `file_path` | נתיב מקורי מה-CSV |
| `file_id` | מזהה קובץ מה-CSV (אם זמין) |
| `entropy` | אנטרופיית Shannon (0.0–8.0) |
| `md5` | גיבוב MD5 |
| `sha256` | גיבוב SHA-256 |
| `file_size` | גודל קובץ בבתים |
| `status` | `ok`, `not_found`, או `read_error` |

#### דוגמאות

**ניתוח אנטרופיה בסיסי:**

```bash
memflow-entropy \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\typed_files.csv
```

**עם תיקיית קבצים פורנזיים מותאמת:**

```bash
memflow-entropy \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\files.csv \
    --forensic-dir C:\Cases\IR-2025-042\raw\recovered_files
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | כל הקבצים עובדו בהצלחה |
| `1` | חלק מהקבצים לא נמצאו או שהייתה שגיאת קריאה |
| `2` | קריטי: CSV הקלט לא נמצא |

---

### 6.7 memflow-alerts-network — זיהוי חריגות רשת (MF-101)

**מטרה:** זיהוי פעילות רשת חשודה ע"י ניתוח יחסי תהליך-פורט, שירותי האזנה, חיבורים חיצוניים בפורטים גבוהים, ושאילתות DNS.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה עם CSVs מוקלדים |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### קבצי קלט נדרשים

| קובץ | חובה | מטרה |
|------|------|------|
| `typed_net.csv` | **כן** | נתוני חיבורי רשת |
| `typed_process.csv` | **כן** | נתוני תהליכים לקורלציית PID |
| `typed_dns.csv` | לא | נתוני שאילתות DNS (משפר זיהוי) |

#### כללי זיהוי

**כלל 1: PROCESS_PORT_MISMATCH (חומרה: MEDIUM)**

תהליך שאינו דפדפן מתקשר על פורט 80 או 443. דפדפנים (Chrome, Firefox, Edge וכו') מוחרגים.

*דוגמה:* `cmd.exe` מתחבר לפורט 443 → התראה.

**כלל 2: LISTENER_TRAP (חומרה: HIGH)**

תהליך במצב LISTENING שאינו ברשימת המאזינים המאושרים. מאזינים מאושרים כוללים: `svchost.exe`, `spoolsv.exe`, `System`, `lsass.exe` ועוד.

*דוגמה:* `evil.exe` מאזין על פורט 4444 → התראה.

**כלל 3: HIGH_PORT_EXTERNAL (חומרה: MEDIUM)**

חיבור לכתובת IP לא-פרטית על פורט > 1024. טווחי IP פרטיים (10.x, 172.16-31.x, 192.168.x, 127.x) מוחרגים.

*דוגמה:* תהליך מתחבר ל-`185.143.42.1:8443` → התראה.

**כלל 4: RARE_DNS_QUERY (חומרה: HIGH)**

PowerShell, cmd.exe, או pwsh.exe מבצעים שאילתת DNS. תהליכים אלה כמעט ולא צריכים לבצע DNS ישירות.

*דוגמה:* `powershell.exe` שואל על `evil-c2-server.com` → התראה.

#### דוגמאות

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

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | אין התראות רשת |
| `1` | נוצרה לפחות התראה אחת |
| `2` | קריטי: `typed_net.csv` או `typed_process.csv` חסרים |

---

### 6.8 memflow-alerts-injection — זיהוי הזרקת קוד (MF-102)

**מטרה:** זיהוי טכניקות הזרקת קוד: הזרקת shellcode (זיכרון RWX ללא גיבוי), חלחול תהליכים (Process Hollowing), תהליכים מוסתרים ע"י DKOM, וטעינת DLL רפלקטיבית.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה עם CSVs מוקלדים |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### קבצי קלט נדרשים

| קובץ | חובה | מטרה |
|------|------|------|
| `typed_findevil.csv` | מועדף | תוצאות FindEvil עם ניתוח VAD |
| `typed_vad.csv` | חלופי | נתוני Virtual Address Descriptor |
| `typed_process.csv` | ל-DKOM | רשימת תהליכים לזיהוי תהליכים מוסתרים |

#### כללי זיהוי

**כלל 1: RWX_UNBACKED (חומרה: CRITICAL)**

אזור זיכרון עם הגנת `PAGE_EXECUTE_READWRITE` ש**אינו מגובה בקובץ על הדיסק**. זהו המזהה הנפוץ ביותר של הזרקת shellcode.

ערכים שמסמנים "ללא גיבוי": מחרוזת ריקה, `-`, `n/a`, `none`, `unknown`, `private`, `pagefile-backed`.

**כלל 2: PROCESS_HOLLOWING (חומרה: CRITICAL)**

תהליך מערכת ידוע (svchost, lsass, csrss, explorer, services וכו') שסעיף ה-Image שלו מצביע לנתיב בלתי צפוי או ריק. זה מצביע על כך שהתהליך הלגיטימי "רוקן" והוחלף בקוד זדוני.

נבדק מול נתיבים קאנוניים (למשל, `svchost.exe` חייב להיות ב-`\Windows\System32\`).

**כלל 3: DKOM_HIDDEN_PROCESS (חומרה: CRITICAL)**

PID מופיע בנתוני FindEvil/VAD אבל **לא** מופיע ב-`typed_process.csv`. זה מרמז שהתהליך הוסתר באמצעות Direct Kernel Object Manipulation (טכניקת rootkit).

**כלל 4: REFLECTIVE_DLL (חומרה: HIGH)**

אזור זיכרון שמכיל כותרת MZ (חתימת PE) אבל ללא קובץ גיבוי. זה מצביע על DLL שנטען ישירות לזיכרון בלי לגעת בדיסק — טכניקת התחמקות נפוצה.

#### דוגמאות

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

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | אין התראות הזרקה |
| `1` | נוצרה לפחות התראה אחת |
| `2` | קריטי: לא `typed_findevil.csv` ולא `typed_vad.csv` נמצאו |

---

### 6.9 memflow-alerts-process — זיהוי תהליכים חשודים (MF-103)

**מטרה:** זיהוי חריגות תהליכים: התחזות בנתיב, אי-התאמת הורה-ילד, typosquatting של שמות בינאריים מערכתיים, ואי-התאמת SID.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה עם `typed_process.csv` |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### קבצי קלט נדרשים

| קובץ | חובה |
|------|------|
| `typed_process.csv` | **כן** |

#### כללי זיהוי

**כלל 1: PATH_MASQUERADE (חומרה: HIGH)**

תהליך עם שם של בינארי מערכתי (svchost, csrss, lsass, services, smss, wininit, winlogon) שרץ מנתיב **מחוץ** ל-`C:\Windows\System32\`. תוקפים לעיתים קרובות קוראים לתוכנות הזדוניות שלהם בשמות תהליכי מערכת אבל ממקמים אותן בתיקיות אחרות.

*דוגמה:* `C:\Users\Public\svchost.exe` → התראה.

**כלל 2: PARENT_CHILD_MISMATCH (חומרה: HIGH)**

יחסי הורה-ילד ידועים מופרים:
- `svchost.exe` חייב להיווצר ע"י `services.exe`.
- יישומי Office (`winword.exe`, `excel.exe`, `outlook.exe` וכו') לא צריכים להפעיל `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, או `mshta.exe`.

*דוגמה:* `outlook.exe` → `powershell.exe` → התראה.

**כלל 3: TYPOSQUATTING (חומרה: MEDIUM)**

שם תהליך עם מרחק Levenshtein < 2 משם בינארי מערכתי קריטי. תוקפים משתמשים בשמות כמו `svhost.exe` או `lssas.exe` כדי להשתלב.

*דוגמה:* `scvhost.exe` (מרחק 1 מ-`svchost.exe`) → התראה.

**כלל 4: SID_MISMATCH (חומרה: HIGH)**

תהליכי מערכת בלבד (`lsass.exe`, `csrss.exe`, `smss.exe`, `wininit.exe`, `services.exe`) שלא רצים תחת חשבון SYSTEM (NT AUTHORITY\SYSTEM / S-1-5-18).

*דוגמה:* `lsass.exe` רץ כמשתמש `john` → התראה.

#### דוגמאות

```bash
memflow-alerts-process \
    --case C:\Cases\IR-2025-042
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | אין התראות תהליכים |
| `1` | נוצרה לפחות התראה אחת |
| `2` | קריטי: `typed_process.csv` לא נמצא |

---

### 6.10 memflow-alerts-persistence — זיהוי מנגנוני התמדה (MF-104)

**מטרה:** זיהוי מנגנוני התמדה במפתחות רגיסטרי Run, שירותים, ומשימות מתוזמנות.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה עם CSVs מוקלדים |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### קבצי קלט נדרשים (לפחות אחד)

| קובץ | מטרה |
|------|------|
| `typed_registry.csv` | ניתוח מפתחות רגיסטרי |
| `typed_services.csv` | ניתוח בינאריים של שירותים |
| `typed_tasks.csv` | ניתוח משימות מתוזמנות |

#### כללי זיהוי

**כלל 1: SUSPICIOUS_RUN_KEY (חומרה: HIGH)**

מפתח רגיסטרי Run או RunOnce שערכו מצביע על נתיב חשוד:
- `%TEMP%`
- `%APPDATA%`
- `\AppData\`
- `\Users\`
- `\ProgramData\`
- `\Downloads\`

*דוגמה:* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `C:\Users\john\AppData\Local\Temp\backdoor.exe` → התראה.

**כלל 2: SERVICE_MASQUERADE (חומרה: HIGH)**

שירות Windows שנתיב הבינארי שלו מכיל קובץ הרצה חשוד:
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `mshta.exe`
- `wscript.exe`
- `rundll32.exe`

*דוגמה:* שירות `UpdateHelper` עם נתיב `powershell.exe -enc <base64>` → התראה.

**כלל 3: HIDDEN_SCHEDULED_TASK (חומרה: MEDIUM)**

משימה מתוזמנת עם פעולה חשודה:
- קידומת `cmd /c`
- `powershell -w hidden`
- `powershell -enc` (פקודה מקודדת)
- הפעלת `mshta`

*דוגמה:* משימה `SystemUpdate` שמריצה `powershell.exe -w hidden -enc SQBFAFgA...` → התראה.

#### דוגמאות

```bash
memflow-alerts-persistence \
    --case C:\Cases\IR-2025-042
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | אין התראות התמדה |
| `1` | נוצרה לפחות התראה אחת |
| `2` | קריטי: אף אחד משלושת ה-CSVs הנדרשים לא נמצא |

---

### 6.11 memflow-alerts-lateral — זיהוי תנועה רוחבית (MF-105)

**מטרה:** זיהוי טכניקות תנועה רוחבית: גניבת הרשאות (credential dumping), מפץ פקודות סיור, ודפוסי הרצה מרחוק.

#### ארגומנטים

| ארגומנט | קיצור | חובה | ברירת מחדל | תיאור |
|---------|-------|------|-----------|--------|
| `--case` | `-c` | **כן** | — | תיקיית שורש החקירה |
| `--in` | `-i` | לא | `<case>/csv/` | תיקייה עם `typed_process.csv` |
| `--out` | `-o` | לא | `<case>/csv/` | תיקיית פלט |
| `--log-level` | `-l` | לא | `INFO` | רמת דיבור |

#### קבצי קלט נדרשים

| קובץ | חובה |
|------|------|
| `typed_process.csv` | **כן** |

#### כללי זיהוי

**כלל 1: CREDENTIAL_DUMP (חומרה: CRITICAL)**

דפוסי שורת פקודה הקשורים לגניבת הרשאות:
- `mimikatz` או `sekurlsa`
- `procdump` שמכוון ל-`lsass`
- `comsvcs.dll` עם `MiniDump`
- `reg save` של רגיסטרי SAM או SECURITY

*דוגמה:* `procdump.exe -ma lsass.exe dump.dmp` → התראה CRITICAL.

**כלל 2: RECON_COMMANDS (חומרה: LOW → HIGH)**

פקודות סיור בודדות מייצרות התראות ברמת LOW. כאשר **3 פקודות סיור שונות או יותר** מקורן מאותו תהליך אב, כולן מוסלמות לרמת HIGH ("מפץ סיור").

פקודות סיור שמזוהות:
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

*דוגמה:* `cmd.exe` (PID 5678) שנוצר ע"י אותו הורה מריץ `whoami`, `ipconfig`, `net user`, `systeminfo` → כולם מוסלמים ל-HIGH.

**כלל 3: REMOTE_EXECUTION (חומרה: HIGH)**

תהליך שירות הרצה מרחוק מפעיל shell:

| הורה (שירות מרחוק) | ילד (Shell) |
|--------------------|-------------|
| `wmiprvse.exe` | `cmd.exe` |
| `wmiapsrv.exe` | `powershell.exe` |
| `services.exe` | `pwsh.exe` |
| `wsmprovhost.exe` | — |

*דוגמה:* `wmiprvse.exe` → `powershell.exe` → התראה HIGH (תנועה רוחבית באמצעות WMI).

#### דוגמאות

```bash
memflow-alerts-lateral \
    --case C:\Cases\IR-2025-042
```

```bash
memflow-alerts-lateral \
    --case C:\Cases\IR-2025-042 \
    --log-level DEBUG
```

#### קודי יציאה

| קוד | מתי |
|-----|-----|
| `0` | אין התראות תנועה רוחבית |
| `1` | נוצרה לפחות התראה אחת |
| `2` | קריטי: `typed_process.csv` לא נמצא |

---

## 7. ספריות משותפות

### 7.1 memflow_common — קריאה וכתיבה בטוחה של CSV

ספרייה זו מספקת את פונקציות הליבה לקריאה וכתיבה של CSV בהן משתמשים כל הכלים.

#### מבני נתונים עיקריים

**`RawTable`** (dataclass):
- `source_path` — נתיב לקובץ המקור
- `headers` — רשימת מחרוזות כותרות עמודות
- `rows` — רשימת רשימות (כל הערכים הם מחרוזות)
- `ingest_errors` — רשימת אובייקטי `IngestError`
- `sha256` — גיבוב SHA-256 של הקובץ הגולמי
- `raw_row_count` — מספר שורות הנתונים בקובץ המקורי

**`IngestError`** (dataclass):
- `line_number` — מספר שורה בקובץ המקור
- `raw_line` — השורה הפגומה כפי שהיא
- `error` — תיאור השגיאה

#### פונקציות

**`read_csv_safe(path) → RawTable`**

קורא קובץ CSV עם אחריות מלאה לאפס-איבוד:
- מנסה קידוד `utf-8-sig` קודם, נופל ל-`latin-1`.
- שורות קצרות מרופדות במחרוזות ריקות (אף פעם לא קורס).
- עמודות עודפות נרשמות כשגיאות חליצה.
- שורות ריקות מדולגות.
- מחשב גיבוב SHA-256 ורושם ספירת שורות.

**`read_csv_safe_linewise(path) → RawTable`**

קורא שורה-שורה כ-fallback לקבצים פגומים ביותר.

**`write_csv_safe(path, headers, rows)`**

כותב קובץ CSV עם `csv.QUOTE_ALL` (כל שדה במרכאות). יוצר תיקיות הורה אם נדרש.

**`write_ingest_errors(path, errors) → Path | None`**

כותב שגיאות חליצה ל-`_ingest_errors.csv`. מחזיר `None` אם אין שגיאות.

### 7.2 memflow_parser — מנוע המרת טיפוסים

ספרייה זו מפעילה את ההמרה מ-Raw ל-Typed CSV.

#### טיפוסים נתמכים

| טיפוס | לוגיקת המרה |
|-------|-------------|
| `raw` / `string` | העברה ישירה — ללא המרה |
| `int` | `int(value.strip())` — דוחה מספרים צפים |
| `hex_int` | מטפל בקידומת `0x` והקסדצימלי חשוף |
| `float` | `float(value.strip())` |
| `bool` | `true/yes/1` → `True`, `false/no/0` → `False` |
| `timestamp` | מנסה מספר פורמטים, כולל Unix epoch |

#### סדר ניתוח Timestamps

הפרסר מנסה את הפורמטים הבאים לפי סדר:

1. `%Y-%m-%dT%H:%M:%S.%f` (ISO עם מיקרו-שניות)
2. `%Y-%m-%dT%H:%M:%S` (ISO)
3. `%Y/%m/%d %H:%M:%S` (מופרד בלוכסנים)
4. `%m/%d/%Y` (תאריך אמריקאי)
5. Unix epoch בשניות (אם מספרי, 10 ספרות)
6. Unix epoch במילישניות (אם מספרי, 13 ספרות)

כל ה-timestamps מוצגים בפורמט ISO 8601: `2025-01-15T08:30:00`.

#### פונקציות עיקריות

**`load_spec(path) → TableSpec`**

מנתח קובץ מפרט YAML באמצעות regex (ללא תלות ב-PyYAML). מחזיר `TableSpec` עם שם טבלה והגדרות עמודות.

**`convert_value(value, type_name) → str | ParseError`**

ממיר ערך מחרוזת בודד לטיפוס המצוין. מחזיר מחרוזת מומרת בהצלחה, או `ParseError` בכישלון.

**`parse_table(raw_table, spec) → TypedTable`**

מחיל מפרט על `RawTable` שלם. מחזיר `TypedTable` עם אותה ספירת שורות. שגיאות נאספות ב-`parse_errors`, לעולם לא גורמות למחיקת שורות.

---

## 8. תהליך עבודה מלא — דוגמה מקצה לקצה

חלק זה מדריך דרך ניתוח פורנזי מלא מ-Memory Dump ועד התראות.

### תרחיש

יש לכם Memory Dump מתגובת אירוע: `C:\Evidence\compromised_server.raw`

תיקיית החקירה תהיה: `C:\Cases\IR-2025-042`

### שלב 1: חילוץ ה-Memory Dump

```bash
memflow-ingest \
    --case C:\Cases\IR-2025-042 \
    --device C:\Evidence\compromised_server.raw \
    --full-dump \
    --wait 30
```

**מה קורה:**
- MemProcFS מנתח את ה-Memory Dump
- כל ה-CSVs הפורנזיים מחולצים ל-`C:\Cases\IR-2025-042\csv\`
- רגיסטרי, בינאריים חשודים, וקבצים משוחזרים מחולצים
- דוח FindEvil נשמר

### שלב 2: מלאי הנתונים שחולצו

```bash
memflow-inventory \
    --case C:\Cases\IR-2025-042
```

**מה קורה:**
- כל CSV ב-`csv/` נסרק
- חריגות מזוהות (קבצים ריקים, כפולים, שגיאות)
- `docs/03_csv_inventory.json` ו-`artifacts/_inventory_manifest.csv` נוצרים

**בדקו בעיות:**

```bash
# הסתכלו על המניפסט לראות מה נמצא
type C:\Cases\IR-2025-042\artifacts\_inventory_manifest.csv
```

### שלב 3: יצירת מפרטי YAML

```bash
memflow-spec-scaffold \
    --case C:\Cases\IR-2025-042
```

**מה קורה:**
- מפרט YAML נוצר לכל טבלה במלאי
- כל העמודות מוגדרות כברירת מחדל כ-`type: "raw"`

**עכשיו ערכו את המפרטים** כדי להקצות טיפוסים נכונים:

פתחו את `memflow_specs/process.yaml` ושנו:

```yaml
columns:
  - name: "pid"
    type: "int"          # היה "raw"
  - name: "ppid"
    type: "int"          # היה "raw"
  - name: "name"
    type: "string"
  - name: "path"
    type: "string"
  - name: "create_time"
    type: "timestamp"    # היה "raw"
```

חזרו על הפעולה עבור `net.yaml`, `registry.yaml`, `vad.yaml` וכו'.

### שלב 4: ניתוח CSVs גולמיים ל-CSVs מוקלדים

```bash
memflow-parse-generic \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv
```

**מה קורה:**
- כל CSV גולמי מומר ל-`typed_<table>.csv`
- המרות טיפוסים מוחלות (מחרוזות → מספרים שלמים, timestamps וכו')
- שגיאות המרה נרשמות ב-`_parsing_errors.csv`

### שלב 5: אימות הנתונים המוקלדים

```bash
memflow-validate \
    --case C:\Cases\IR-2025-042
```

**מה קורה:**
- ספירות שורות מאומתות (בדיקת שוויון)
- עמודות מוקלדות נבדקות לערכי null (בדיקת אילוצים)
- PIDs בין טבלאות מאומתים (בדיקת יחסים)
- דוח Markdown נכתב ל-`artifacts/validation_report.md`

### שלב 6: הרצת ניתוח אנטרופיה

```bash
memflow-entropy \
    --case C:\Cases\IR-2025-042 \
    --in C:\Cases\IR-2025-042\csv\typed_files.csv \
    --forensic-dir C:\Cases\IR-2025-042\raw\recovered_files
```

**מה קורה:**
- כל קובץ שמוזכר ב-CSV נקרא
- אנטרופיית Shannon, MD5, SHA-256 מחושבים
- תוצאות נכתבות ל-`csv/file_entropy.csv`
- קבצים עם אנטרופיה > 7.0 דורשים חקירה נוספת

### שלב 7: הרצת כל גלאי ההתראות

```bash
# חריגות רשת
memflow-alerts-network \
    --case C:\Cases\IR-2025-042

# הזרקת קוד
memflow-alerts-injection \
    --case C:\Cases\IR-2025-042

# תהליכים חשודים
memflow-alerts-process \
    --case C:\Cases\IR-2025-042

# מנגנוני התמדה
memflow-alerts-persistence \
    --case C:\Cases\IR-2025-042

# תנועה רוחבית
memflow-alerts-lateral \
    --case C:\Cases\IR-2025-042
```

### שלב 8: סקירת תוצאות

לאחר הרצת כל הכלים, תיקיית החקירה נראית כך:

```
C:\Cases\IR-2025-042\
├── csv\
│   ├── process.csv              # גולמי
│   ├── net.csv                  # גולמי
│   ├── registry.csv             # גולמי
│   ├── ... (CSVs גולמיים נוספים)
│   ├── typed_process.csv        # מוקלד
│   ├── typed_net.csv            # מוקלד
│   ├── typed_registry.csv       # מוקלד
│   ├── ... (CSVs מוקלדים נוספים)
│   ├── file_entropy.csv         # תוצאות אנטרופיה
│   ├── alerts_network.csv       # התראות רשת
│   ├── alerts_injection.csv     # התראות הזרקה
│   ├── alerts_process.csv       # התראות תהליכים
│   ├── alerts_persistence.csv   # התראות התמדה
│   ├── alerts_lateral.csv       # התראות תנועה רוחבית
│   ├── _parsing_errors.csv      # שגיאות המרה
│   └── _inventory_manifest.csv  # מניפסט מלאי
├── raw\
│   ├── registry\                # רגיסטרי שחולץ
│   ├── dumps\                   # Minidumps של תהליכים
│   ├── files\                   # קבצים פתוחים
│   └── recovered_files\         # קבצים שנחצבו
├── artifacts\
│   ├── _inventory_manifest.csv
│   └── validation_report.md
├── docs\
│   ├── 03_csv_inventory.json
│   └── findevil_raw.txt
└── logs\
    └── *.log
```

### סקריפט אוטומציה

ניתן לשרשר את כל השלבים לסקריפט PowerShell יחיד:

```powershell
$CASE = "C:\Cases\IR-2025-042"
$DEVICE = "C:\Evidence\compromised_server.raw"

# צינור עיבוד
memflow-ingest       -c $CASE -d $DEVICE --full-dump --wait 30
memflow-inventory    -c $CASE
memflow-spec-scaffold -c $CASE
# (ערכו מפרטים ידנית כאן, או השתמשו במפרטים מוכנים מראש)
memflow-parse-generic -c $CASE -i "$CASE\csv"
memflow-validate     -c $CASE

# ניתוח
memflow-entropy           -c $CASE -i "$CASE\csv\typed_files.csv"
memflow-alerts-network    -c $CASE
memflow-alerts-injection  -c $CASE
memflow-alerts-process    -c $CASE
memflow-alerts-persistence -c $CASE
memflow-alerts-lateral    -c $CASE

Write-Host "הצינור הושלם. בדקו $CASE לתוצאות."
```

---

## 9. מבנה תיקיות — מדריך מלא

### מבנה תיקיית חקירה

| נתיב | נוצר ע"י | תיאור |
|------|----------|--------|
| `<case>/csv/` | ingest, parse | קבצי CSV גולמיים ומוקלדים |
| `<case>/csv/typed_*.csv` | parse-generic | גרסאות מוקלדות של CSVs גולמיים |
| `<case>/csv/alerts_*.csv` | כלי התראות | תוצאות התראות אבטחה |
| `<case>/csv/file_entropy.csv` | entropy | תוצאות ניתוח אנטרופיה |
| `<case>/csv/_parsing_errors.csv` | parse-generic | שגיאות המרת טיפוסים |
| `<case>/csv/_ingest_errors.csv` | ingest | שגיאות חליצת CSV גולמי |
| `<case>/artifacts/` | inventory, validate | דוחות ומניפסטים |
| `<case>/artifacts/_inventory_manifest.csv` | inventory | מניפסט שטוח של כל ה-CSVs |
| `<case>/artifacts/validation_report.md` | validate | תוצאות בדיקות אימות |
| `<case>/docs/` | inventory, ingest | ארטיפקטי תיעוד |
| `<case>/docs/03_csv_inventory.json` | inventory | מלאי JSON מלא |
| `<case>/docs/findevil_raw.txt` | ingest (--full-dump) | דוח FindEvil |
| `<case>/raw/registry/` | ingest (--full-dump) | רגיסטרי שחולץ |
| `<case>/raw/dumps/` | ingest (--full-dump) | Minidumps של תהליכים |
| `<case>/raw/files/` | ingest (--full-dump) | קבצים פתוחים |
| `<case>/raw/recovered_files/` | ingest (--full-dump) | קבצים שנחצבו |
| `<case>/logs/` | כל הכלים | קבצי לוג לכל הרצה |

---

## 10. טבלת קודי יציאה

| קוד | משמעות | פעולה |
|-----|--------|-------|
| `0` | **הצלחה** — כל הפעולות הושלמו ללא בעיות | המשיכו לשלב הבא בצינור |
| `1` | **כשלון חלקי** — נוצר פלט, אך עם אזהרות/שגיאות | סקרו לוגים, המשיכו בזהירות |
| `2` | **קריטי** — לא ניתן להמשיך (קלט חסר, תלות חסרה) | תקנו את הבעיה לפני ניסיון חוזר |

### פירוט קודי יציאה לפי כלי

| כלי | יציאה 0 | יציאה 1 | יציאה 2 |
|-----|---------|---------|---------|
| `memflow-ingest` | כל ה-CSVs חולצו | חלק מהחילוצים נכשלו | memprocfs חסר, device חסר, timeout ב-VFS |
| `memflow-inventory` | אין חריגות | חריגות נמצאו | תיקיית סריקה חסרה |
| `memflow-spec-scaffold` | מפרטים נוצרו | — | JSON מלאי חסר |
| `memflow-parse-generic` | אין שגיאות המרה | שגיאות המרה (נתונים עדיין יוצרו) | מפרט/קלט חסר |
| `memflow-validate` | כל הבדיקות עוברות | כשלונות בבדיקות | תיקיית typed/מניפסט חסרים |
| `memflow-entropy` | כל הקבצים עובדו | קבצים לא נמצאו | CSV קלט חסר |
| `memflow-alerts-*` | אין התראות | התראות נוצרו | CSV קלט נדרש חסר |

---

## 11. פתרון בעיות

### "memprocfs not installed"

```
ERROR: memprocfs package is required for ingestion. Install with: pip install memprocfs
```

**פתרון:** הריצו `pip install memprocfs` או `pip install .` מתיקיית שורש הפרויקט.

### "CSV directory never appeared within N seconds"

מערכת הקבצים הוירטואלית של MemProcFS לא ייצרה פלט CSV בזמן.

**פתרונות:**
- הגדילו את זמן ההמתנה: `--wait 60`
- וודאו שקובץ ה-Memory Dump תקין ולא פגום
- וודאו שיש מספיק RAM (MemProcFS צריך זיכרון לניתוח ה-dump)

### "No matching spec found for X.csv"

הפרסר לא מוצא מפרט YAML לקובץ CSV הנתון.

**פתרונות:**
- הריצו `memflow-spec-scaffold` קודם ליצירת מפרטים
- בדקו ששם קובץ המפרט תואם לשם ה-CSV (למשל, `process.csv` → `process.yaml`)
- וודאו שתיקיית `--specs` נכונה

### חריגת "Empty data" במלאי

לקובץ CSV יש כותרות אבל אפס שורות נתונים.

**זה מידע, לא בהכרח שגיאה.** חלק מטבלאות MemProcFS עשויות להיות ריקות באופן לגיטימי אם הנתונים המתאימים לא היו קיימים ב-Memory Dump.

### בעיות קידוד

MemFlow מנסה `utf-8-sig` קודם, ואז נופל ל-`latin-1`. אם אתם עדיין רואים טקסט משובש:

- בדקו את קידוד ה-CSV המקורי
- MemFlow **לעולם לא יקרוס** על שגיאות קידוד — במקרה הגרוע, תווים עשויים להיראות לא נכון אבל כל הנתונים נשמרים

### קבצים עם אנטרופיה גבוהה

אם `file_entropy.csv` מציג קבצים עם אנטרופיה > 7.5:

- זה **לא** אומר אוטומטית שהקובץ זדוני
- קבצים דחוסים (`.zip`, `.7z`), קבצים מוצפנים, וקבצי הרצה ארוזים — כולם בעלי אנטרופיה גבוהה
- הצלבו עם ההתראות וניתוח התהליכים להקשר

---

*גרסת מסמך: 1.0 — שלב 6 הפצה*
*נוצר עבור MemFlow v0.6.0*

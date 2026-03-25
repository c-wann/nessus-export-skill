# nessus-export-skill

A **GitHub Copilot CLI skill** that exports Nessus vulnerability scan results to **Excel (.xlsx)** and native **.nessus** format using Chrome browser automation — no API keys required.

## What it does

1. Opens the Nessus web portal (`https://127.0.0.1:8834`) in a headless Chrome window
2. Logs in via the browser UI login form
3. Clicks the portal's own **Export → Nessus** button to download the `.nessus` XML
4. Scrapes the vulnerability table to match the **exact row count shown in the UI**
5. Combines UI data + XML details into a colour-coded Excel workbook
6. Saves both a clean `.nessus` file and the Excel file

## Output

Each run produces two files:

| File | Description |
|---|---|
| `nessus_<LABEL>_vulnerabilities.xlsx` | Colour-coded Excel with 4 sheets |
| `nessus_<LABEL>_vulnerabilities.nessus` | Native Nessus XML (re-importable) |

### Excel Sheets

| Sheet | Description |
|---|---|
| **Summary** | Host info, severity counts |
| **Vulnerabilities (N)** | Exact match to Nessus UI table |
| **All Findings (N)** | Every individual finding with full details |
| **Critical & High** | High-priority findings for remediation |

## Installation

```bash
npx skills add github:c-wann/nessus-export-skill
```

Or manually:
```bash
mkdir -p ~/.agents/skills/nessus-export
curl -o ~/.agents/skills/nessus-export/SKILL.md \
  https://raw.githubusercontent.com/c-wann/nessus-export-skill/main/SKILL.md
curl -o ~/.agents/skills/nessus-export/nessus_export_tool.py \
  https://raw.githubusercontent.com/c-wann/nessus-export-skill/main/nessus_export_tool.py
pip3 install selenium openpyxl webdriver-manager
```

## Requirements

- Python 3.10+
- Google Chrome installed
- `pip3 install selenium openpyxl webdriver-manager`
- Nessus running at `https://127.0.0.1:8834` (or any custom URL)

## Usage

### Via Copilot CLI (with skill installed)

Just ask naturally:
> *"Export Nessus scan 19 host 2"*  
> *"Export vulnerabilities from https://127.0.0.1:8834/#/scans/reports/19/hosts/2/vulnerabilities"*

### Direct command line

```bash
python3 ~/.agents/skills/nessus-export/nessus_export_tool.py \
  --url   https://127.0.0.1:8834 \
  --user  admin \
  --pass  admin \
  --scan  19 \
  --host  2 \
  --label GETS_PRD_168 \
  --outdir ~/
```

### Parameters

| Flag | Default | Description |
|---|---|---|
| `--url` | `https://127.0.0.1:8834` | Nessus portal URL |
| `--user` | `admin` | Nessus username |
| `--pass` | *(prompt)* | Nessus password |
| `--scan` | *(required)* | Scan ID (from URL) |
| `--host` | *(required)* | Host ID (from URL) |
| `--label` | `scan{N}_host{N}` | Label for output filenames |
| `--outdir` | `~/` | Output directory |

## Severity Colour Coding

| Severity | Colour |
|---|---|
| 🔴 Critical | `#FF0000` |
| 🟠 High | `#FF6600` |
| 🟡 Medium | `#FFCC00` |
| 🟢 Low | `#66CC00` |
| 🔵 Info | `#99CCFF` |
| 🟣 Mixed | `#CC99FF` |

## Notes

- Runs **headless** (no visible browser window)
- Self-signed certificates are handled automatically
- The `.nessus` file is the unmodified export from the portal — re-importable into any Nessus instance
- "UI count" = grouped vulnerability entries shown in the portal; "findings count" = total individual `ReportItem` entries in the XML

## HTML Reports

Generate standalone HTML reports from a `.nessus` file:

```bash
python3 ~/.agents/skills/nessus-export/nessus_html_report.py \
  ~/nessus_GETS_PRD_168_vulnerabilities.nessus \
  --label GETS_PRD_168
```

Produces:
- `<LABEL>_by_host.html` — vulnerabilities grouped by host, sorted by severity
- `<LABEL>_by_plugin.html` — vulnerabilities grouped by plugin/CVE with affected hosts

### HTML Report Features
- 🎨 Colour-coded severity rows (Critical → Info)
- 📋 Collapsible cards — Expand/Collapse all
- 🔗 Clickable CVE links to cve.org
- 🗂 Sticky sidebar TOC
- 🖨 Print-friendly
- 🔁 Cross-linked (By Host ↔ By Plugin nav bar)

> Nessus Essentials free tier does not support built-in HTML reports.
> This generates equivalent reports directly from the `.nessus` XML.

## License

MIT

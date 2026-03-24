---
name: nessus-export
description: "Export Nessus vulnerability scan results to Excel (.xlsx) and native .nessus format. Uses Selenium + Chrome to access the Nessus web portal at https://127.0.0.1:8834, logs in via the browser UI, exports the scan using the built-in Export button, scrapes the vulnerability table to match the exact count shown in the UI, and produces colour-coded Excel + .nessus files. USE FOR: export nessus vulnerabilities, nessus scan to excel, nessus report export, download nessus results, vulnerability export, nessus to xlsx, nessus scan report, get nessus vulnerabilities."
license: MIT
metadata:
  author: iDler
  version: "1.0.0"
---

# Nessus Export Skill

Export vulnerability scan results from the local Nessus portal (`https://127.0.0.1:8834`) to Excel and `.nessus` format files using Chrome browser automation.

## When to Use This Skill

Load and follow this skill when the user asks to:
- Export a Nessus scan or vulnerability report
- Download vulnerabilities from Nessus to Excel
- Get scan results for a specific host or scan ID
- Re-run a Nessus export for a different scan/host

## Prerequisites Check

Before running, verify these are available:
```bash
python3 --version          # needs 3.10+
pip3 show selenium openpyxl webdriver-manager 2>/dev/null | grep Name
```

If any are missing, install them:
```bash
pip3 install selenium openpyxl webdriver-manager -q
```

## Workflow

### Step 1 — Gather parameters from the user

Ask the user (or infer from context) for:

| Parameter | Default | Description |
|---|---|---|
| `NESSUS_URL` | `https://127.0.0.1:8834` | Nessus portal URL |
| `USERNAME` | `admin` | Nessus login username |
| `PASSWORD` | `admin` | Nessus login password |
| `SCAN_ID` | (required) | Numeric scan ID from the URL, e.g. `19` from `#/scans/reports/19/...` |
| `HOST_ID` | (required) | Numeric host ID from the URL, e.g. `2` from `.../hosts/2/...` |
| `HOST_LABEL` | (optional) | Human label for output filenames, e.g. `GETS_PRD_168` |
| `OUTPUT_DIR` | `~/` (home) | Where to save output files |

The scan ID and host ID can be read directly from the Nessus URL the user provides, e.g.:
`https://127.0.0.1:8834/#/scans/reports/19/hosts/2/vulnerabilities`
→ SCAN_ID=19, HOST_ID=2

### Step 2 — Run the export script

The skill script is bundled at:
```
~/.agents/skills/nessus-export/nessus_export_tool.py
```

Run it with the collected parameters:
```bash
python3 ~/.agents/skills/nessus-export/nessus_export_tool.py \
  --url    NESSUS_URL \
  --user   USERNAME \
  --pass   PASSWORD \
  --scan   SCAN_ID \
  --host   HOST_ID \
  --label  HOST_LABEL \
  --outdir OUTPUT_DIR
```

Example for a scan at `#/scans/reports/19/hosts/2/vulnerabilities`:
```bash
python3 ~/.agents/skills/nessus-export/nessus_export_tool.py \
  --url https://127.0.0.1:8834 \
  --user admin --pass admin \
  --scan 19 --host 2 \
  --label GETS_PRD_168
```

### Step 3 — Verify outputs

After the script completes, verify both files exist:
```bash
ls -lh ~/nessus_<LABEL>_vulnerabilities.xlsx
ls -lh ~/nessus_<LABEL>_vulnerabilities.nessus
```

Then open the Excel:
```bash
open ~/nessus_<LABEL>_vulnerabilities.xlsx
```

### Step 4 — Report results to the user

Tell the user:
- The exact file paths for both outputs
- The vulnerability counts: UI groups total AND individual findings total
- Severity breakdown table (Critical / High / Medium / Low / Info / Mixed)

## Output Files

Each run produces two files in `OUTPUT_DIR`:

| File | Format | Description |
|---|---|---|
| `nessus_<LABEL>_vulnerabilities.xlsx` | Excel | Colour-coded workbook with 4 sheets |
| `nessus_<LABEL>_vulnerabilities.nessus` | XML | Native Nessus format, re-importable into Nessus |

### Excel Sheets

| Sheet | Description |
|---|---|
| **Summary** | Host IP, OS, MAC, severity counts |
| **Vulnerabilities (N)** | Exact match to Nessus UI table — one row per UI group |
| **All Findings (N)** | Every individual finding with port, protocol, CVE, CVSS, synopsis, solution, plugin output |
| **Critical & High** | Filtered view of critical and high severity findings only |

### Severity Colour Coding

| Severity | Colour |
|---|---|
| Critical | 🔴 Red `#FF0000` |
| High | 🟠 Orange `#FF6600` |
| Medium | 🟡 Yellow `#FFCC00` |
| Low | 🟢 Green `#66CC00` |
| Info | 🔵 Blue `#99CCFF` |
| Mixed | 🟣 Purple `#CC99FF` |

## How It Works (Technical)

1. **Chrome automation** — Selenium + ChromeDriver opens a headless Chrome window
2. **Login** — Fills the Nessus web UI login form (no API keys needed)
3. **Export via UI** — Clicks the portal's own **Export → Nessus** button to download the `.nessus` XML
4. **UI scraping** — Navigates to `#/scans/reports/{SCAN_ID}/hosts/{HOST_ID}/vulnerabilities` and scrapes the vulnerability table rows (matching the exact count shown in the UI)
5. **XML parsing** — Parses the downloaded `.nessus` XML for full details (CVE, CVSS, synopsis, description, solution, plugin output)
6. **Excel build** — Combines UI rows + XML details into a formatted, colour-coded workbook

## Troubleshooting

| Problem | Fix |
|---|---|
| Login failed | Verify `--user` / `--pass` credentials |
| ChromeDriver mismatch | Run `pip3 install --upgrade webdriver-manager` |
| Download timeout | Nessus may be slow; the script waits 60s |
| 0 rows scraped | Check SCAN_ID and HOST_ID match the URL |
| Certificate error | Already handled with `--ignore-certificate-errors` |

## Notes

- The `.nessus` file downloaded is the **unmodified** export from the Nessus portal — it can be re-imported into any Nessus instance
- The UI "vulnerability count" (e.g. 49) counts **grouped entries** (Multiple Issues rows count as one). The "findings" count (e.g. 249) is the total individual ReportItems in the XML
- The script runs **headless** (no visible browser window)

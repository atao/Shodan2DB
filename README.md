# Shodan2DB

🔌 Utility designed to parse Shodan JSON exports, store them into an optimized SQLite database, and generate comprehensive HTML vulnerability exposure reports.

## Purpose

The primary objective of this tool is to centralize Shodan export data into a structured SQLite environment for advanced querying and infrastructure monitoring.

**Account Restriction Bypass :** Shodan JSON exports natively include valuable fields like `"vulns"` and `"tags"` regardless of your tier. This tool extracts these premium attributes—normally locked behind expensive Small Business, Corporate, or Enterprise API accounts—and surfaces them directly for analysis.

## Key Features

- **Blazing Fast Imports:** Leverages SQLite WAL (Write-Ahead Logging) and atomic transaction batching, reducing disk I/O bottlenecks. Perfect for running on lightweight hardware.
- **Robust Exception Handling:** Implements defensive data extraction wrappers preventing common `KeyError` crashes caused by incomplete Shodan geographic metadata.
- **Dynamic HTML Indexing:** Generates responsive, elegant dashboards styled with **Bulma CSS** and **Bootstrap Icons**, complete with client-side filtering and real-time live search.
- **Strict Data Integrity:** Enforces database-level composite unique constraints (`UNIQUE(ip, cveid)`) preventing redundant storage overhead during overlapping historical imports.

## Requirements

Ensure your local execution environment satisfies the necessary dependencies:

```bash
pip install -r requirements.txt
```

## Usage and Options

```bash
Usage: shodan2db.py [OPTIONS] COMMAND [ARGS]...

  Shodan2DB CLI tool for parsing Shodan JSON exports and generating HTML
  reports.

Options:
  --help  Show this message and exit.

Commands:
  export  Generate an HTML report from the data in the database.
  parse   Parse the Shodan JSON export file and store data in the database.
```

### Command : parse

```bash
Usage: shodan2db.py parse [OPTIONS]

  Parse the Shodan JSON export file and store data in the database.

Options:
  -i, --input-file FILE  JSON or JSON.GZ export file from Shodan.  [required]
  -d, --database FILE    Target database name or path.  [required]
  -v, --verbose          Verbose mode.
  -h, --help             Show this message and exit.
```

### Command : export

```bash
Usage: shodan2db.py export [OPTIONS]

  Generate an HTML report from the data in the database.

Options:
  -d, --database FILE       Path to the SQLite database file.  [required]
  -o, --report-file FILE    Output path for the HTML report file.  [default:
                            shodan.html]
  -t, --template-file FILE  Path to the Jinja2 template file.  [default:
                            templates/report.html]
  -v, --verbose             Verbose mode.
  -h, --help                Show this message and exit.
```

## Quickstart

1. Query Shodan via the web interface and click on **"Download Results"**.

<img src="img/Shodan Export.png">

2. Select the number of results to download.

<img src="img/Shodan Results.png">

3. Download your results.

<img src="img/Shodan Download.png">

4. Import your results and compile your threat report utilizing the CLI sequences:

```bash
# Step 1: Parse and seed your structured SQLite layer
python shodan2db.py parse -i ./example_shodan.json -d ./example_database.db -v

# Step 2: Extract analytics and output your HTML dashboard
python shodan2db.py export -d ./example_database.db -o ./example_report.html -v
```

5. See report file :

- Dataset summary

  <img src="img/report.png">

- Host details

  <img src="img/report2.png">

**Tags** and **vulns** are visible directly in the **Summary** table.

<img src="img/Summary.png">

## Database Architecture

Upon initialization, the tool optimizes SQLite pragmas and automatically structures the underlying relational objects:

- **`services`**: Houses core operational network service logs, banners, geo-coordinates, ISP allocations, and metadata.
- **`vulnerabilities`**: Stores indexed granular mappings of CVE IDs alongside their verified CVSS scores and threat summary descriptions.
- **`Summary` (View)**: An internal prioritized virtual evaluation layer sorting network entities by physical exposure risk (`nbvulns DESC`).

## Templates Customization

The presentation architecture is entirely modular. You can seamlessly customize the structural layout or interface themes inside `templates/report.html`. 

The default layout leverages **Bulma CSS** to render high-contrast, professional cybersecurity matrices with custom conditional coloring for CVSS threat scales.

## Development

You can import `Shodan2DB` directly into third-party automated playbooks or continuous integration loops as a native Python class:

```python
from shodan2db import Shodan2DB

# Programmatically trigger parsing and reporting
Shodan2DB.prepare_database(verbose=True, database="production_audit")
Shodan2DB.parser(verbose=True, inputfile="raw_shodan.json", database="production_audit")
Shodan2DB.export(verbose=True, exportfile="exposure.html", database="production_audit", template_file="templates/report.html")
```
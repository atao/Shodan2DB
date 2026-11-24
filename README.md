# Shodan2DB
This tool generates a report on the attack surface exposed on the internet based on Shodan exports.

Shodan exports include vulnerability data and tags (`vuln` and `tag`) that aren’t directly accessible online or through subscriptions such as Small Business, Corporate, or Enterprise.
This tool unlocks that data, enabling deeper vulnerability analysis and helping teams develop effective remediation plans.

You can display results on [Osintracker](https://app.osintracker.com).

`vuln` and `tag` are available with Membership plan.

You can sometimes find a Shodan lifetime membership on sale for as little as $4 or $5 during special events, such as the platform’s anniversary or Black Friday. The regular price is $49 as a one-time payment, with no annual renewal fee.

Reports use a Jinja2 template that you can replace with your own (see [Templates Customization](#templates-customization)).

## Features

- **Attack surface inventory** covering exposed hosts, services, ports, and technologies.
- **Vulnerable host inventory** with vulnerability counts and affected services.
- **CVE information** including CVSS scores, verification status, and vulnerability summaries.
- **Consolidated CVE statistics** to highlight recurring and widespread vulnerabilities.
- **Exposure analysis** to support risk-based remediation prioritization.
- **Shodan export support** for JSON and compressed JSON.GZ files.
- **Local SQLite storage** for services, network metadata, tags, and vulnerabilities.
- **Vulnerability deduplication** per IP address, service port and CVE.
- **HTML report generation** with sortable tables and client-side search.
- **Customizable reports** using a Jinja2 template.
- **Osintracker export** as a JSON graph of IPs, host/domain names and their relations.

## Installation

Requires Python 3.10 or later and an export obtained through Shodan’s supported export features.

Install the `shodan2db` command with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/atao/Shodan2DB
```

Or run it from a clone without installing anything:

```bash
uv run shodan2db --help
```

Without uv: `python -m pip install .` from a clone.

## Commands

```bash
Usage: shodan2db [OPTIONS] COMMAND [ARGS]...

  Parse Shodan JSON exports into SQLite and generate HTML / osintracker
  reports.

Options:
  -V, --version  Show the version and exit.
  -h, --help     Show this message and exit.

Commands:
  export  Export the database as an HTML report, an osintracker JSON...
  parse   Parse a Shodan export and store it into a SQLite database.
```

### Command : parse

```bash
Usage: shodan2db parse [OPTIONS]

  Parse a Shodan export and store it into a SQLite database.

Options:
  -i, --input-file FILE  JSON or JSON.GZ export file from Shodan.  [required]
  -d, --database FILE    Target database name or path (.db is added if
                         missing).  [required]
  -v, --verbose          Verbose mode.
  -h, --help             Show this message and exit.
```

Importing the same export twice is safe: banners already stored (same IP, port, transport and scan time) and CVEs already linked to a port are skipped.

### Command : export

```bash
Usage: shodan2db export [OPTIONS]

  Export the database as an HTML report, an osintracker JSON file, or both.

Options:
  -d, --database FILE            Path to the SQLite database file.  [required]
  -f, --format [html|osint|all]  Which export(s) to generate.  [default: all]
  -o, --output FILE              Output path for the HTML report.  [default:
                                 shodan.html]
  -t, --template-file FILE       Jinja2 template for the HTML report.
                                 [default: (built-in report.html)]
  --osint TEXT                   Central entity name for the osintracker
                                 export.  [default: shodan]
  --osint-output FILE            Output path for the osintracker JSON file.
                                 [default: assets_osintracker.json]
  -v, --verbose                  Verbose mode.
  -h, --help                     Show this message and exit.
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
shodan2db parse -i ./example_shodan.json -d ./example_database.db -v

# Step 2: Extract analytics and output your HTML dashboard
shodan2db export -d ./example_database.db -f html -o ./example_report.html -v

# Optional - HTML dashboard + JSON for Osintracker import (default format: all)
shodan2db export -d ./example_database.db -o ./example_report.html --osint example --osint-output example_osintracker -v
```


5. See report file :

- Dataset summary

  <img src="img/report.png">

- Host details

  <img src="img/report2.png">

- [Osintracker](https://app.osintracker.com) export

  <img src="img/osintracker.png">

**Tags** and **vulns** are visible directly in the **Summary** table.

<img src="img/Summary.png">

## Database Architecture

The schema is versioned (`PRAGMA user_version`); databases created by older releases are upgraded automatically the first time they are opened.

- **`services`**: one row per Shodan banner (IP, port, transport, scan time): service, banner, location, ISP and tags.
- **`vulnerabilities`**: one row per CVE and service port, with its CVSS score, verification status and summary.
- **`Summary` (View)**: services sorted by vulnerability count (`nbvulns DESC`).

## Templates Customization

The built-in template is [src/shodan2db/templates/report.html](src/shodan2db/templates/report.html). To customize it, copy it anywhere and pass your copy with `-t` (editing the installed file would be overwritten by updates):

```bash
shodan2db export -d audit.db -f html -t ./my_report.html -o audit.html
```

The template receives `vulns_hosts` and `all_hosts` (each host with its `services` and `vulns`), `cves`, `total_hosts`, `total_services` and `total_vulns`.

The default layout uses **Bulma CSS** and **Bootstrap Icons** loaded from a CDN: opening the report requires internet access for its styling.

## Development

```bash
uv run pytest                                      # tests
uv run ruff check . && uv run ruff format --check . # lint
```

The package can also be used as a library:

```python
from shodan2db import export_html, export_osintracker, parse_file

parse_file("raw_shodan.json.gz", "production_audit.db", verbose=True)
export_html("production_audit.db", "exposure.html")
export_osintracker("production_audit.db", "exposure_osintracker.json", alias="Audit")
```

Errors (missing file, invalid database or template) are raised as `shodan2db.Shodan2DBError`.

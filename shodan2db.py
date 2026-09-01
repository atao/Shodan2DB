import gzip
import json
import os
import sqlite3
import sys

import click
from jinja2 import Environment, FileSystemLoader, TemplateError

# Import osinttracker exporter module
from plugins.export_osinttracker import OsintTrackerExporter


class Shodan2DB:
    """
    Handles SQLite database initialization, data parsing from Shodan JSON files,
    and HTML report generation for vulnerability metrics.
    """

    # Static method to create tables, views, and indexes in the SQLite database
    @staticmethod
    def init_database(verbose, database):
        """
        Initializes the SQLite database schema, creates indexes, and applies performance tweaks.
        """
        # Ensure the database file has the correct extension
        if not database.endswith(".db"):
            database = f"{database}.db"

        if verbose:
            print("[+] Initializing database schema and performance tweaks...")

        try:
            # Use context manager for automatic connection handling, commit, and rollback
            with sqlite3.connect(database) as conn:
                cursor = conn.cursor()

                # PERFORMANCE TWEAKS: Enable WAL mode and normal synchronous writing
                # Crucial for bulk inserts (Shodan data) to prevent SD card/disk I/O bottlenecks
                cursor.execute("PRAGMA journal_mode = WAL;")
                cursor.execute("PRAGMA synchronous = NORMAL;")

                # Create 'services' table with standard auto-incrementing primary key syntax
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS services (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        ip TEXT,  
                        asn TEXT,  
                        hostnames TEXT, 
                        domains TEXT, 
                        org TEXT,  
                        timestamp TEXT,  
                        isp TEXT,  
                        os TEXT,  
                        product TEXT,  
                        version TEXT, 
                        transport TEXT,  
                        port TEXT, 
                        data TEXT,  
                        city TEXT,  
                        region_code TEXT,  
                        area_code TEXT, 
                        country_code TEXT,  
                        country_name TEXT,  
                        nbvulns INTEGER, 
                        tags TEXT
                    )
                """)

                # Create 'vulnerabilities' table with a composite unique constraint
                # Prevents duplicate CVE tracking per IP when parsing overlapping Shodan files
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        ip TEXT, 
                        cveid TEXT, 
                        verified NUMERIC,
                        cvss REAL, 
                        summary TEXT,
                        UNIQUE(ip, cveid) ON CONFLICT IGNORE
                    )
                """)

                # Create 'Summary' view for quick analytics sorted by vulnerability count
                cursor.execute("""
                    CREATE VIEW IF NOT EXISTS Summary AS 
                    SELECT ip, hostnames, port, product, version, transport, isp, city, tags, nbvulns 
                    FROM services 
                    ORDER BY nbvulns DESC
                """)

                # CREATE INDEXES: Dramatically speeds up search queries and HTML report generation
                cursor.execute("CREATE INDEX IF NOT EXISTS ip_index ON services(ip);")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS nbvulns_index ON services(nbvulns);"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS vulns_ip_index ON vulnerabilities(ip);"
                )

        # Transaction is automatically committed upon exiting the 'with' block if no errors occur

        except sqlite3.Error as e:
            print(
                f"[-] Critical SQLite error during database preparation: {e}",
                file=sys.stderr,
            )
            raise e

    @staticmethod
    def parser(verbose, inputfile, database):
        """
        Parses a JSON or JSON.GZ file line by line and bulk inserts
        network service and vulnerability records into a SQLite database.
        """
        # Ensure the database file has the correct extension
        if not database.endswith(".db"):
            database = f"{database}.db"
        if verbose:
            print("[+] Parsing file and bulk inserting data...")

        try:
            # Open a single database connection for the entire file processing
            with sqlite3.connect(database) as conn:
                # PERFORMANCE TWEAKS: Enable WAL mode and reduce sync frequency
                # Crucial to speed up bulk inserts and extend SD card/disk lifespan
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                cursor = conn.cursor()

                # Automatically handle gzipped compressed files (.gz) vs raw text files
                is_gzip = inputfile.endswith(".gz")
                open_func = gzip.open if is_gzip else open
                open_mode = "rt" if is_gzip else "r"

                # Process the input file line by line to minimize memory usage
                with open_func(
                    inputfile, mode=open_mode, encoding="utf-8"
                ) as json_file:
                    for line_idx, line in enumerate(json_file, 1):
                        # Skip empty lines
                        if not line.strip():
                            continue

                        # Validate and parse the JSON line structure
                        try:
                            jsonobject = json.loads(line)
                        except json.JSONDecodeError:
                            print(
                                f"[!] Skipping line {line_idx}: Invalid JSON structure."
                            )
                            continue

                        # Extract core identification and network data
                        ip_str = jsonobject.get("ip_str")
                        asn = jsonobject.get("asn")

                        # Flatten lists into space-separated strings for SQLite storage
                        domains = (
                            " ".join(jsonobject.get("domains"))
                            if jsonobject.get("domains")
                            else None
                        )
                        hostnames = (
                            " ".join(jsonobject.get("hostnames"))
                            if jsonobject.get("hostnames")
                            else None
                        )
                        tags = (
                            " ".join(jsonobject.get("tags"))
                            if jsonobject.get("tags")
                            else None
                        )

                        # Extract service and software specific fields
                        org = jsonobject.get("org")
                        timestamp = jsonobject.get("timestamp")
                        isp = jsonobject.get("isp")
                        operating_system = jsonobject.get("os")
                        product = jsonobject.get("product")
                        version = jsonobject.get("version")
                        transport = jsonobject.get("transport")
                        port = jsonobject.get("port")
                        data = jsonobject.get("data")

                        # Safe extraction of nested location attributes to avoid KeyError
                        location = jsonobject.get("location", {})
                        city = location.get("city")
                        region_code = location.get("region_code")
                        area_code = location.get("area_code")
                        country_code = location.get("country_code")
                        country_name = location.get("country_name")

                        # Evaluate vulnerability data presence
                        vulns = jsonobject.get("vulns")
                        nbvulns = len(vulns) if vulns is not None else None

                        # Execute service records batch insertion
                        try:
                            cursor.execute(
                                "INSERT OR IGNORE INTO services (ip, asn, domains, hostnames, org, timestamp, isp, os, "
                                "product, version, transport, port, data, city, region_code, area_code, country_code, "
                                "country_name, nbvulns, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (
                                    ip_str,
                                    asn,
                                    domains,
                                    hostnames,
                                    org,
                                    timestamp,
                                    isp,
                                    operating_system,
                                    product,
                                    version,
                                    transport,
                                    port,
                                    data,
                                    city,
                                    region_code,
                                    area_code,
                                    country_code,
                                    country_name,
                                    nbvulns,
                                    tags,
                                ),
                            )
                        except sqlite3.Error as e:
                            print(f"[!] Database error on service line {line_idx}: {e}")
                            continue

                        # Execute associated vulnerability records insertion if sub-items exist
                        if vulns:
                            for cveid, vuln_data in vulns.items():
                                verified = vuln_data.get("verified")
                                cvss = vuln_data.get("cvss")
                                summary = vuln_data.get("summary")

                                try:
                                    cursor.execute(
                                        "INSERT OR IGNORE INTO vulnerabilities (ip, cveid, verified, cvss, summary) "
                                        "VALUES (?, ?, ?, ?, ?)",
                                        (
                                            ip_str,
                                            cveid,
                                            verified,
                                            cvss,
                                            summary,
                                        ),
                                    )
                                except sqlite3.Error as e:
                                    print(
                                        f"[!] Database error on vuln {cveid} (line {line_idx}): {e}"
                                    )
                                    continue

                # Single atomic batch commit after parsing all rows successfully
                conn.commit()

        except FileNotFoundError:
            print(
                f'[!] Error: Provided input file "{inputfile}" does not exist!',
                file=sys.stderr,
            )
            sys.exit(1)
        except sqlite3.Error as e:
            print(f"[-] Critical database connection error: {e}", file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def export(verbose, exportfile, database, template_file):
        """
        Fetches vulnerability data from SQLite, correlates host metrics,
        and renders an HTML report using a Jinja2 template structure.
        """
        # Ensure the export report file has the correct HTML extension
        if not exportfile.endswith(".html"):
            exportfile = f"{exportfile}.html"

        # Ensure the database file has the correct extension
        if not database.endswith(".db"):
            database = f"{database}.db"

        if verbose:
            print(f"[+] Fetching data from {database}...")

        try:
            # Open database connection using context manager for safe cleanup
            with sqlite3.connect(database) as conn:
                # Map column names to object keys allowing Jinja2 syntax like {{ host.ip }}
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Fetch distinct vulnerable hosts sorted by total vulnerability count
                cursor.execute("""
                    SELECT DISTINCT ip, hostnames, isp, city, tags, nbvulns FROM summary
                    WHERE nbvulns > 0 ORDER BY nbvulns DESC
                """)
                vulns_hosts_list = cursor.fetchall()

                # Keep hosts without reported vulnerabilities for the final inventory table.
                cursor.execute("""
                    SELECT DISTINCT ip, hostnames, isp, city, tags FROM summary
                    WHERE nbvulns IS NULL OR nbvulns = 0 ORDER BY ip
                """)
                all_hosts_list = cursor.fetchall()

                cursor.execute("SELECT COUNT(*) AS total FROM summary")
                total_hosts = cursor.fetchone()["total"]

                # Fetch individual vulnerabilities ordered by IP and severity level
                cursor.execute("""
                    SELECT ip, cveid, cvss, summary FROM vulnerabilities 
                    ORDER BY ip, cvss DESC
                """)
                vulns_list = cursor.fetchall()

                # Fetch target services bound to vulnerable network hosts
                cursor.execute("""
                    SELECT DISTINCT ip, port, product, version, transport, data FROM services
                    WHERE ip IN (SELECT ip FROM summary WHERE nbvulns > 0) ORDER BY ip
                """)
                services_list = cursor.fetchall()

                # Fetch services for the complete non-vulnerable host inventory.
                cursor.execute("""
                    SELECT DISTINCT ip, port, product, version, transport, data FROM services
                    WHERE ip IN (SELECT ip FROM summary WHERE nbvulns IS NULL OR nbvulns = 0)
                    ORDER BY ip, port
                """)
                all_services_list = cursor.fetchall()

                # Fetch consolidated statistics for recurring CVEs across infrastructure
                cursor.execute("""
                    SELECT cveid, count(*) as count, cvss, summary FROM vulnerabilities 
                    GROUP BY cveid ORDER BY count DESC, cvss DESC
                """)
                cves_list = cursor.fetchall()

        except sqlite3.OperationalError as e:
            print(f"[!] Database error: {e}", file=sys.stderr)
            print("[!] Please provide a valid database name.", file=sys.stderr)
            sys.exit(1)

        # FIX: This block is now outside the except block, resolving the unreachable code issue
        if verbose:
            print("[+] Rendering template and generating HTML report...")

        # Dynamically separate directories to support flexible template locations
        template_dir = os.path.dirname(template_file) or "templates"
        template_name = os.path.basename(template_file)

        try:
            # Initialize Jinja2 environment with targeted storage directories
            environment = Environment(loader=FileSystemLoader(template_dir))
            template = environment.get_template(template_name)

            # Map dataset lists directly onto targeted template fields
            content = template.render(
                vulns_hosts=vulns_hosts_list,
                all_hosts=all_hosts_list,
                total_hosts=total_hosts,
                services=services_list,
                all_services=all_services_list,
                vulns=vulns_list,
                cves=cves_list,
            )

            # Write compiled content structure safely into output document
            with open(exportfile, mode="w", encoding="utf-8") as message:
                message.write(content)

            if verbose:
                print(f"[+] Wrote report : {exportfile}")

        except TemplateError as err:
            print(
                f"[!] Jinja2 template rendering error: {err}",
                file=sys.stderr,
            )
            sys.exit(1)

        except OSError as err:
            print(
                f"[!] File system I/O error writing report: {err}",
                file=sys.stderr,
            )
            sys.exit(1)

    @staticmethod
    def export_osinttracker(verbose, database, output_file, alias):
        """
        Export Shodan2DB data to osinttracker JSON format.
        Creates entities (IPs, domains, hostnames) and relationships between them.
        """
        # Ensure the database file has the correct extension
        if not database.endswith(".db"):
            database = f"{database}.db"

        if verbose:
            print(f"[+] Exporting to osinttracker format...")

        try:
            # Create exporter instance and export
            exporter = OsintTrackerExporter(database, verbose, alias)
            exporter.export_to_json(output_file)

            if verbose:
                print(f"[+] osinttracker export completed successfully!")

        except FileNotFoundError as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error: {e}", file=sys.stderr)
            sys.exit(1)


# Define the click group to organize commands
@click.group()
def cli():
    """
    Shodan2DB CLI tool for parsing Shodan JSON exports and generating HTML reports.
    """
    pass


# Define the parse command with options for input file, database, and verbose mode
@click.command(
    name="parse",
    help="Parse the Shodan JSON export file and store data in the database.",
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.option(
    "--input-file",
    "-i",
    help="JSON or JSON.GZ export file from Shodan.",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    "--database",
    "-d",
    help="Target database name or path.",
    required=True,
    type=click.Path(file_okay=True, dir_okay=False, writable=True),
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode.")
def parse(verbose, database, input_file):
    """
    Parse exported file from Shodan and store into a SQLite database.
    """
    Shodan2DB.init_database(verbose=verbose, database=database)
    Shodan2DB.parser(verbose=verbose, database=database, inputfile=input_file)


# Define the export command with options for database, report file, and verbose mode
@click.command(
    name="export",
    help="Export data from database (HTML report or osinttracker JSON).",
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.option(
    "--database",
    "-d",
    help="Path to the SQLite database file.",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output path for HTML report file.",
    type=click.Path(writable=True, file_okay=True, dir_okay=False),
)
@click.option(
    "--template-file",
    "-t",
    default="templates/report.html",
    help="Path to the Jinja2 template file (HTML export only).",
    show_default=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    "--osint",
    default="shodan",
    is_flag=False,
    flag_value="shodan",
    type=str,
    help="Central entity name for osinttracker export (default: shodan).",
)
@click.option(
    "--osint-output",
    default="assets_osinttracker.json",
    type=str,
    help="Output path for osinttracker JSON file.",
    show_default=True,
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode.")
def export(verbose, database, output, template_file, osint, osint_output):
    """
    Export data from the database.

    Generates both HTML report and osinttracker JSON format.

    Examples:
        Default files:                 shodan2db.py export -d database.db
        Custom HTML path:              shodan2db.py export -d database.db -o rapport.html
        Custom entity:                 shodan2db.py export -d database.db --osint "Campaign"
        Custom osinttracker output:    shodan2db.py export -d database.db --osint-output custom.json
    """
    # Always generate HTML report
    if output is None:
        output = "shodan.html"
    Shodan2DB.export(
        verbose=verbose,
        database=database,
        exportfile=output,
        template_file=template_file,
    )

    # Always generate osinttracker JSON with the specified entity name
    Shodan2DB.export_osinttracker(
        verbose=verbose,
        database=database,
        output_file=osint_output,
        alias=osint,
    )


# Add the parse and export commands to the CLI group
cli.add_command(parse)
cli.add_command(export)

# Main execution block
if __name__ == "__main__":
    if len(sys.argv) == 1:
        cli.main(["--help"])
    else:
        cli()

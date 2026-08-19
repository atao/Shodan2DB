import json
import sqlite3
import sys
import os
import click
from jinja2 import Environment, FileSystemLoader


class Shodan2DB:
    # Static method to create tables and views in the SQLite database
    @staticmethod
    def prepare_database(verbose, database):
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

    # Static method to parse a JSON file and insert data into the database
    @staticmethod
    def parser(verbose, inputfile, database):
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

                # Process the input file line by line to minimize memory usage
                with open(inputfile, encoding="utf-8") as json_file:
                    for line_idx, line in enumerate(json_file, 1):
                        # Skip empty lines
                        if not line.strip():
                            continue

                        # Validate and parse the JSON line structure
                        try:
                            jsonobject = json.loads(line)
                        except json.JSONDecodeError:
                            print(f"[!] Skip line {line_idx}: Invalid JSON structure.")
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
                                        (ip_str, cveid, verified, cvss, summary),
                                    )
                                except sqlite3.Error as e:
                                    print(
                                        f"[!] Database error on vuln {cveid} (line {line_idx}): {e}"
                                    )
                                    continue

                # Single atomical batch commit after parsing all rows successfully
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

    # Static method to generate an HTML report from the database data
    @staticmethod
    def export(verbose, exportfile, database, template_file):
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
                    WHERE nbvulns IS NOT NULL ORDER BY nbvulns DESC
                """)
                hosts_list = cursor.fetchall()

                # Fetch individual vulnerabilities ordered by IP and severity level
                cursor.execute("""
                    SELECT ip, cveid, cvss, summary FROM vulnerabilities 
                    ORDER BY ip, cvss DESC
                """)
                vulns_list = cursor.fetchall()

                # Fetch target services bound to vulnerable network hosts
                cursor.execute("""
                    SELECT DISTINCT ip, port, product, version, transport FROM services
                    WHERE ip IN (SELECT ip FROM summary WHERE nbvulns IS NOT NULL) ORDER BY ip
                """)
                services_list = cursor.fetchall()

                # Fetch consolidated statistics for recurring CVEs across infrastructure
                cursor.execute("""
                    SELECT cveid, count(*) as count, cvss, summary FROM vulnerabilities 
                    GROUP BY cveid ORDER BY count DESC, cvss DESC
                """)
                cves_list = cursor.fetchall()

        except sqlite3.OperationalError as e:
            print(f"[!] Database error: {e}", file=sys.stderr)
            print(f"[!] Please provide a valid database name.", file=sys.stderr)
            sys.exit(1)

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
                hosts=hosts_list,
                services=services_list,
                vulns=vulns_list,
                cves=cves_list,
            )

            # Write compiled content structure safely into output document
            with open(exportfile, mode="w", encoding="utf-8") as message:
                message.write(content)

            if verbose:
                print(f"[+] Wrote report : {exportfile}")

        except Exception as e:
            print(
                f"[!] Error during template rendering or file writing: {e}",
                file=sys.stderr,
            )
            sys.exit(1)


# Define the click group to organize commands
@click.group()
def cli():
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
    help="JSON export file from Shodan.",
    required=True,
    type=click.Path(exists=True),
)
@click.option(
    "--database", "-d", help="Database name or path.", required=True, type=str
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode.")
def parse(verbose, database, input_file):
    """
    Parse the Shodan JSON export file and store data in the database.
    """
    Shodan2DB.prepare_database(verbose=verbose, database=database)
    Shodan2DB.parser(verbose=verbose, database=database, inputfile=input_file)


# Define the export command with options for database, report file, and verbose mode
@click.command(
    name="export",
    help="Generate an HTML report from the data in the database.",
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.option(
    "--database",
    "-d",
    help="Path to the SQLite database file.",
    required=True,
    type=click.Path(exists=True),
)
@click.option(
    "--report-file",
    "-o",
    default="shodan.html",
    help="Output path for the HTML report file.",
    show_default=True,
    type=click.Path(writable=True),
)
@click.option(
    "--template-file",
    "-t",
    default="templates/report.html",
    help="Path to the Jinja2 template file.",
    show_default=True,
    type=click.Path(exists=True),
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode.")
def export(verbose, database, report_file, template_file):
    """
    Generate an HTML report from the data in the database.
    """
    Shodan2DB.export(
        verbose=verbose,
        database=database,
        exportfile=report_file,
        template_file=template_file,
    )


# Add the parse and export commands to the CLI group
cli.add_command(parse)
cli.add_command(export)

# Main execution block
if __name__ == "__main__":
    # Show help message if no arguments are provided
    if len(sys.argv) == 1:
        cli.main(["--help"])
    else:
        # Check template existence globally only if invoking the export command implicitly
        if "export" in sys.argv and not any(
            arg in sys.argv for arg in ["-t", "--template-file"]
        ):
            if not os.path.exists("templates") or not os.path.isfile(
                "templates/report.html"
            ):
                print(
                    "[!] Error: Default 'templates/report.html' not found. "
                    "Please create it or use -t to specify a template.",
                    file=sys.stderr,
                )
                sys.exit(2)

        # Execute the CLI application
        cli()

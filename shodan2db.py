import json
import sqlite3
import sys
import os
import click
from jinja2 import Environment, FileSystemLoader


class Shodan2DB():
    # Static method to create tables and views in the SQLite database
    @staticmethod
    def prepare_database(verbose, database):
        if not database.endswith(".db"):
            database = "{}.db".format(database)
        # Create database
        try:
            if verbose:
                print("[+] Create views and tables...")
            conn = sqlite3.connect(database)
            cursor = conn.cursor()
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS "services" ( "id" INTEGER UNIQUE, "ip" TEXT,  "asn" TEXT,  "hostnames" 
                TEXT, "domains" TEXT, "org" TEXT,  "timestamp" TEXT,  "isp" TEXT,  "os" TEXT,  "product" TEXT,  
                "version" TEXT, "transport" TEXT,  "port" TEXT, "data" TEXT,  "city" TEXT,  "region_code" TEXT,  
                "area_code" TEXT, "country_code" TEXT,  "country_name" TEXT,  "nbvulns" INTEGER, "tags" TEXT, 
                PRIMARY KEY("id" AUTOINCREMENT) )""")
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS "vulnerabilities" ( "ip" TEXT, "cveid" TEXT, "verified" NUMERIC,
                "cvss" REAL, "summary" TEXT)""")
            cursor.execute(
                """CREATE VIEW IF NOT EXISTS "Summary" AS select ip, hostnames, port, product, version, transport, isp,
                city, tags, nbvulns FROM services ORDER BY nbvulns DESC""")
            cursor.execute("""CREATE INDEX IF NOT EXISTS "ip_index" ON services("ip");""")
            cursor.execute("""CREATE INDEX IF NOT EXISTS "nbvulns_index" ON services("nbvulns");""")
            conn.commit()
        except Exception as e:
            print("Error")
            conn.rollback()
            raise e
        finally:
            conn.close()

    # Static method to parse a JSON file and insert data into the database
    @staticmethod
    def parser(verbose, inputfile, database):
        if not database.endswith(".db"):
            database = "{}.db".format(database)
        if verbose:
            print("[+] Parsing file...")
        try:
            with open(inputfile) as jsonFile:
                for line in jsonFile:
                    jsonobject = json.loads(line)

                    # Mapping data
                    ip_str = jsonobject.get('ip_str')
                    asn = jsonobject.get('asn')
                    if jsonobject.get('domains') is not None:
                        domains = jsonobject.get('domains')
                        domains = " ".join(domains)
                    else:
                        domains = None
                    hostnames = jsonobject.get('hostnames')
                    hostnames = " ".join(hostnames)
                    org = jsonobject.get('org')
                    timestamp = jsonobject.get('timestamp')
                    isp = jsonobject.get('isp')
                    os = jsonobject.get('os')
                    product = jsonobject.get('product')
                    version = jsonobject.get('version')
                    transport = jsonobject.get('transport')
                    port = jsonobject.get('port')
                    data = jsonobject.get('data')
                    city = jsonobject['location']['city']
                    region_code = jsonobject['location']['region_code']
                    area_code = jsonobject['location']['area_code']
                    country_code = jsonobject['location']['country_code']
                    country_name = jsonobject['location']['country_name']
                    if jsonobject.get('vulns') is not None:
                        nbvulns = len(jsonobject.get('vulns'))
                    else:
                        nbvulns = None
                    tags = jsonobject.get('tags')
                    if tags is not None:
                        tags = " ".join(tags)

                    # Insertion services
                    try:
                        conn = sqlite3.connect(database)
                        cursor = conn.cursor()
                        cursor.execute(
                            'INSERT OR IGNORE INTO services (ip, asn, domains, hostnames, org, timestamp, isp, os, '
                            'product,'
                            'version, transport, port, data, city, region_code, area_code, country_code, country_name,'
                            'nbvulns, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            (
                                ip_str, asn, domains, hostnames, org, timestamp, isp, os, product, version, transport,
                                port,
                                data,
                                city, region_code, area_code, country_code, country_name, nbvulns, tags,))
                        # id = cursor.lastrowid
                        # print('Last id insert : %d' % id, "-", line)
                        conn.commit()
                    except sqlite3.IntegrityError:
                        print("[!] Already exist :", line)
                        continue
                    except Exception as e:
                        print("[!] Error")
                        conn.rollback()
                        raise e
                    finally:
                        conn.close()
                    if nbvulns is not None:
                        for i in jsonobject['vulns']:
                            cveid = i
                            verified = jsonobject['vulns'][i]['verified']
                            cvss = jsonobject['vulns'][i]['cvss']
                            summary = jsonobject['vulns'][i]['summary']

                            # Insertion vulnerabilities
                            try:
                                conn = sqlite3.connect(database)
                                cursor = conn.cursor()
                                cursor.execute(
                                    'INSERT OR IGNORE INTO vulnerabilities (ip, cveid, verified, cvss, summary)'
                                    'VALUES (?, ?, ?, ?, ?)',
                                    (ip_str, cveid, verified, cvss, summary,))
                                # id = cursor.lastrowid
                                # print('Last id insert : %d' % id, "-", line)
                                conn.commit()
                            except sqlite3.IntegrityError:
                                print("[!] Already exist :", line)
                                continue
                            except Exception as e:
                                print("[!] Error")
                                conn.rollback()
                                raise e
                            finally:
                                conn.close()
                    else:
                        pass
        except:
            print('[!] Error: Provided input file does not exist!')
            exit(1)

    # Static method to generate an HTML report from the database data
    @staticmethod
    def export(verbose, exportfile, database, template_file):
        if not exportfile.endswith(".html"):
            exportfile = "{}.html".format(exportfile)
        if not database.endswith(".db"):
            database = "{}.db".format(database)
        try:
            conn = sqlite3.connect(database)
            cursor = conn.cursor()
            cursor.execute(
                """SELECT DISTINCT ip, hostnames, isp, city, tags, nbvulns FROM summary
                WHERE nbvulns IS NOT NULL ORDER BY nbvulns DESC""")
            hosts_list = cursor.fetchall()
            cursor.execute("""SELECT ip, cveid, cvss, summary FROM vulnerabilities ORDER BY ip, cvss DESC""")
            vulns_list = cursor.fetchall()
            cursor.execute(
                """SELECT DISTINCT ip, port, product, version, transport FROM services
                WHERE ip IN (SELECT ip FROM summary WHERE nbvulns is not NULL) ORDER BY ip""")
            services_list = cursor.fetchall()
            cursor.execute(
                """SELECT cveid, count(*) as count, cvss, summary from vulnerabilities GROUP BY cveid ORDER BY count 
                DESC, cvss DESC""")
            cves_list = cursor.fetchall()
        except sqlite3.OperationalError:
            print("[!] {} not found! Please provide a valid database name with -d".format(database))
            exit(1)

        # Transformation of lists into dictionaries for easier template editing.
        hosts_data = []
        for row in hosts_list:
            hosts = {"ip": row[0], "hostnames": row[1], "isp": row[2], "city": row[3], "tags": row[4],
                     "nbvulns": row[5]}
            hosts_data.append(hosts)

        services_data = []
        for row in services_list:
            services = {"ip": row[0], "port": row[1], "product": row[2], "version": row[3], "transport": row[4]}
            services_data.append(services)

        vulns_data = []
        for row in vulns_list:
            vulns = {"ip": row[0], "cveid": row[1], "cvss": row[2], "summary": row[3]}
            vulns_data.append(vulns)

        cves_data = []
        for row in cves_list:
            cves = {"cveid": row[0], "count": row[1], "cvss": row[2], "summary": row[3]}
            cves_data.append(cves)

        environment = Environment(loader=FileSystemLoader("templates/"))
        template = environment.get_template(template_file)
        filename = exportfile
        content = template.render(
            hosts=hosts_data,
            services=services_data,
            vulns=vulns_data,
            cves=cves_data
        )
        with open(filename, mode="w", encoding="utf-8") as message:
            message.write(content)
            if verbose:
                print(f"[+] Wrote report : {filename}")


# Define the click group to organize commands
@click.group()
def cli():
    pass


# Define the parse command with options for input file, database, and verbose mode
@click.command(name="parse", help="Parse the Shodan JSON export file and store data in the database.",
               context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--input-file', '-i', help='JSON export file from Shodan.', required=True, type=click.Path(exists=True))
@click.option('--database', '-d', help='Database name.', required=True, show_default=True, type=str)
@click.option('--verbose', '-v', is_flag=True, help="Verbose mode.")
def parse(verbose, database, input_file):
    """
    Parse the Shodan JSON export file and store data in the database.
    """
    # Since the required=True attribute is set, Click will automatically enforce that these options are provided
    Shodan2DB.prepare_database(verbose=verbose, database=database)
    Shodan2DB.parser(verbose=verbose, database=database, inputfile=input_file)


# Define the export command with options for database, report file, and verbose mode
def validate_database(ctx, param, value):
    if not value:
        raise click.MissingParameter(ctx=ctx, param=param, message='Please specify a database using --database.')
    return value


@click.command(name="export", help="Generate an HTML report from the data in the database.",
               context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--database', '-d', callback=validate_database, help='Path to the SQLite database file.',
              type=click.Path(exists=True), required=True)
@click.option('--report-file', '-o', default='shodan.html', help='Output path for the HTML report file.',
              show_default=True, type=click.Path(writable=True))
@click.option('--template-file', '-t', default='report.html', help='Template used for the report.',
              show_default=True)
@click.option('--verbose', '-v', is_flag=True, help="Verbose mode.")
def export(verbose, database, report_file, template_file):
    """
    Generate an HTML report from the data in the database.
    """
    # With the callback validation, no need for an explicit check here
    Shodan2DB.export(verbose=verbose, database=database, exportfile=report_file, template_file=template_file)


# Add the parse and export commands to the CLI group
cli.add_command(parse)
cli.add_command(export)

# Main execution block
if __name__ == '__main__':
    # Show help message if no arguments are provided
    if len(sys.argv) == 1:
        cli.main(['--help'])
    else:
        if not os.path.exists("templates"):
            raise SystemExit("Templates folder doesn't exist.", 2)
        elif not os.path.isfile("templates/report.html"):
            raise SystemExit("Default report.html doesn't exist.", 2)
        else:
            # Execute the CLI commands
            cli()

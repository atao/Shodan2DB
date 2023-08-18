import json
import sqlite3
import sys

import click
from jinja2 import Environment, FileSystemLoader


# Functions
def initdb(verbose, database):
    # Create database
    try:
        if verbose:
            print("[+] Create views and tables...")
        conn = sqlite3.connect(database)
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS "services" ( "id" INTEGER UNIQUE, "ip" TEXT,  "asn" TEXT,  "hostnames" TEXT,
            "domains" TEXT, "org" TEXT,  "timestamp" TEXT,  "isp" TEXT,  "os" TEXT,  "product" TEXT,  "version" TEXT,
            "transport" TEXT,  "port" TEXT, "data" TEXT,  "city" TEXT,  "region_code" TEXT,  "area_code" TEXT,
            "country_code" TEXT,  "country_name" TEXT,  "nbvulns" INTEGER, "tags" TEXT,
            PRIMARY KEY("id" AUTOINCREMENT) )""")
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS "vulnerabilities" ( "ip" TEXT, "cveid" TEXT, "verified" NUMERIC,
            "cvss" REAL, "summary" TEXT)""")
        cursor.execute(
            """CREATE VIEW IF NOT EXISTS "Summary" AS select ip, hostnames, port, product, version, transport, isp,
            city, tags, nbvulns FROM services ORDER BY nbvulns DESC""")
        conn.commit()
    except Exception as e:
        print("Error")
        conn.rollback()
        raise e
    finally:
        conn.close()


def parser(verbose, inputfile, database):
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
                        'INSERT OR IGNORE INTO services (ip, asn, domains, hostnames, org, timestamp, isp, os, product,'
                        'version, transport, port, data, city, region_code, area_code, country_code, country_name,'
                        'nbvulns, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (ip_str, asn, domains, hostnames, org, timestamp, isp, os, product, version, transport, port,
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


def export(verbose, exportfile, database):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT DISTINCT ip, hostnames, isp, city, tags, nbvulns FROM summary
        WHERE nbvulns IS NOT NULL ORDER BY nbvulns DESC""")
    hosts_list = cursor.fetchall()
    cursor.execute("""SELECT ip, cveid, cvss, summary FROM vulnerabilities ORDER BY ip, cvss DESC""")
    vulns_list = cursor.fetchall()
    cursor.execute(
        """SELECT ip, port, product, version, transport FROM services
        WHERE ip IN (SELECT ip FROM summary WHERE nbvulns is not NULL) ORDER BY ip""")
    services_list = cursor.fetchall()
    cursor.execute("""SELECT cveid, count(*) as count from vulnerabilities GROUP BY cveid ORDER BY count DESC""")
    cves_list = cursor.fetchall()

    # Transformation of lists into dictionaries for easier template editing.
    hosts_data = []
    for row in hosts_list:
        hosts = {"ip": row[0], "hostnames": row[1], "isp": row[2], "city": row[3], "tags": row[4], "nbvulns": row[5]}
        hosts_data.append(hosts)

    services_data = []
    for row in services_list:
        services = {"ip": row[0], "port": row[1], "product": row[2], "version": row[3], "transport": row[4]}
        services_data.append(services)

    vulns_data = []
    for row in vulns_list:
        vulns = {"ip": row[0], "cveid": row[1], "cvss": row[2], "summary": row[3], }
        vulns_data.append(vulns)

    environment = Environment(loader=FileSystemLoader("templates/"))
    template = environment.get_template("report.html")
    filename = exportfile
    content = template.render(
        hosts=hosts_data,
        services=services_data,
        vulns=vulns_data,
        cves=cves_list
    )
    with open(filename, mode="w", encoding="utf-8") as message:
        message.write(content)
        if verbose:
            print(f"[+] Wrote report : {filename}")


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version='1', prog_name="Shodan2DB")
@click.option('--verbose', '-v', is_flag=True, help="Verbose mode")
@click.option('--database', '-d', default='shodan.db', help='Database name', show_default=True, type=str)
@click.option('--inputfile', '-i', help='Json export file from Shodan', required=True, type=str)
@click.option('--exportfile', '-o', default='shodan.html', help='Output report HTML file', show_default=True, type=str)
def cli(verbose, database, inputfile, exportfile):
    initdb(verbose, database)
    parser(verbose, inputfile, database)
    export(verbose, exportfile, database)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        cli.main(['--help'])
    else:
        cli()

# SELECT cveid, count(*) as count from vulnerabilities GROUP BY cveid ORDER BY count DESC

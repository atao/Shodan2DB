import json
import sqlite3
import sys

import click


# Functions
def initdb(verbose, database):
    # Create database
    try:
        if verbose:
            print("[+] Create views and tables...")
        # printIfVerbose(verbose, '[+] Create views and tables...')
        conn = sqlite3.connect(database)
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS "services" ( "id" INTEGER UNIQUE, "ip" TEXT,  "asn" TEXT,  "hostnames" TEXT,  "domains" TEXT,  "org" TEXT,  "timestamp" TEXT,  "isp" TEXT,  "os" TEXT,  "product" TEXT,  "version" TEXT,  "transport" TEXT,  "port" TEXT,  "data" TEXT,  "city" TEXT,  "region_code" TEXT,  "area_code" TEXT,  "country_code" TEXT,  "country_name" TEXT,  "nbvulns" INTEGER,  "tags" TEXT,  PRIMARY KEY("id" AUTOINCREMENT) )""")
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS "vulnerabilities" ( "ip" TEXT, "cveid" TEXT, "verified" NUMERIC, "cvss" REAL, "summary" TEXT)""")
        cursor.execute(
            """CREATE VIEW IF NOT EXISTS "Summary" AS select ip, port, product, version, transport, isp, city, tags, nbvulns from services ORDER BY nbvulns DESC""")
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
                        'INSERT OR IGNORE INTO services (ip, asn, domains, hostnames, org, timestamp, isp, os, product, version, transport, port, data, city, region_code, area_code, country_code, country_name, nbvulns, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
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
                                'INSERT OR IGNORE INTO vulnerabilities (ip, cveid, verified, cvss, summary) VALUES (?, ?, ?, ?, ?)',
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


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version='1.0.0', prog_name="Shodan Parser")
@click.option('--verbose', '-v', is_flag=True, help="Verbose mode")
@click.option('--database', '-d', default='shodan.db', help='Database name', show_default=True, type=str)
@click.option('--inputfile', '-i', help='Json export file from Shodan', required=True, type=str)
def cli(verbose, database, inputfile):
    initdb(verbose, database)
    parser(verbose, inputfile, database)


if __name__ == '__main__':
    if len(sys.argv) == 1:

        cli.main(['--help'])
    else:
        cli()

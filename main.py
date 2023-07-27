import json
import sqlite3
import click
import sys


# Functions
def initDB(verbose, database):
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


def parser(verbose, input, database):
    if verbose:
        print("[+] Parsing file...")
    try:
        with open(input) as jsonFile:
            for line in jsonFile:
                jsonObject = json.loads(line)

                # Mapping data
                ip_str = jsonObject.get('ip_str')
                asn = jsonObject.get('asn')
                try:
                    domains = jsonObject.get('domains')
                    domains = " ".join(domains)
                except:
                    domains = None
                hostnames = jsonObject.get('hostnames')
                hostnames = " ".join(hostnames)
                org = jsonObject.get('org')
                timestamp = jsonObject.get('timestamp')
                isp = jsonObject.get('isp')
                os = jsonObject.get('os')
                product = jsonObject.get('product')
                version = jsonObject.get('version')
                transport = jsonObject.get('transport')
                port = jsonObject.get('port')
                data = jsonObject.get('data')
                city = jsonObject['location']['city']
                region_code = jsonObject['location']['region_code']
                area_code = jsonObject['location']['area_code']
                country_code = jsonObject['location']['country_code']
                country_name = jsonObject['location']['country_name']
                try:
                    nbvulns = len(jsonObject.get('vulns'))
                except:
                    nbvulns = None

                try:
                    tags = jsonObject.get('tags')
                    tags = " ".join(tags)
                except:
                    tags = None

                # Insertion services
                try:
                    conn = sqlite3.connect(database)
                    cursor = conn.cursor()
                    cursor.execute(
                        'INSERT OR IGNORE INTO services (ip, asn, domains, hostnames, org, timestamp, isp, os, product, version, transport, port, data, city, region_code, area_code, country_code, country_name, nbvulns, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (ip_str, asn, domains, hostnames, org, timestamp, isp, os, product, version, transport, port,
                         data,
                         city, region_code, area_code, country_code, country_name, nbvulns, tags,))
                    id = cursor.lastrowid
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
                if nbvulns != None:
                    for i in jsonObject['vulns']:
                        cveid = i
                        verified = jsonObject['vulns'][i]['verified']
                        cvss = jsonObject['vulns'][i]['cvss']
                        summary = jsonObject['vulns'][i]['summary']

                        # Insertion vulnerabilities
                        try:
                            conn = sqlite3.connect(database)
                            cursor = conn.cursor()
                            cursor.execute(
                                'INSERT OR IGNORE INTO vulnerabilities (ip, cveid, verified, cvss, summary) VALUES (?, ?, ?, ?, ?)',
                                (ip_str, cveid, verified, cvss, summary,))
                            id = cursor.lastrowid
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
@click.option('--input', '-i', help='Json export file from Shodan', required=True, type=str)
def cli(verbose, database, input):
    initDB(verbose, database)
    parser(verbose, input, database)


if __name__ == '__main__':
    if len(sys.argv) == 1:

        cli.main(['--help'])
    else:
        cli()
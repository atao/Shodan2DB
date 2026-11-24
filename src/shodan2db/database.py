"""SQLite storage for Shodan banners: schema, migrations and import."""

import gzip
import json
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path

# Stored in PRAGMA user_version. Databases without it (version 0) come from
# releases that stored the port as TEXT and keyed CVEs by (ip, cveid) only.
SCHEMA_VERSION = 2

SERVICE_COLUMNS = (
    "ip",
    "asn",
    "hostnames",
    "domains",
    "org",
    "timestamp",
    "isp",
    "os",
    "product",
    "version",
    "transport",
    "port",
    "data",
    "city",
    "region_code",
    "area_code",
    "country_code",
    "country_name",
    "nbvulns",
    "tags",
)

_TABLES = (
    """
    CREATE TABLE services (
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
        port INTEGER,
        data TEXT,
        city TEXT,
        region_code TEXT,
        area_code TEXT,
        country_code TEXT,
        country_name TEXT,
        nbvulns INTEGER,
        tags TEXT,
        -- A Shodan banner is identified by host, port, transport and scan time
        UNIQUE (ip, port, transport, timestamp)
    )
    """,
    """
    CREATE TABLE vulnerabilities (
        ip TEXT,
        port INTEGER,
        cveid TEXT,
        verified NUMERIC,
        cvss REAL,
        summary TEXT,
        UNIQUE (ip, port, cveid)
    )
    """,
)

_INDEXES_AND_VIEWS = (
    "CREATE INDEX IF NOT EXISTS ip_index ON services(ip)",
    "CREATE INDEX IF NOT EXISTS nbvulns_index ON services(nbvulns)",
    "CREATE INDEX IF NOT EXISTS vulns_ip_index ON vulnerabilities(ip)",
    """
    CREATE VIEW IF NOT EXISTS Summary AS
    SELECT ip, hostnames, port, product, version, transport, isp, city, tags, nbvulns
    FROM services
    ORDER BY nbvulns DESC
    """,
)

_INSERT_SERVICE = (
    f"INSERT OR IGNORE INTO services ({', '.join(SERVICE_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(SERVICE_COLUMNS))})"
)
_INSERT_VULN = (
    "INSERT OR IGNORE INTO vulnerabilities (ip, port, cveid, verified, cvss, summary) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)
# CVEs migrated from version 0 have no port; drop them once the same CVE is
# imported again with its port, so the report does not list it twice.
_DROP_SUPERSEDED_VULNS = """
    DELETE FROM vulnerabilities
    WHERE port IS NULL AND EXISTS (
        SELECT 1 FROM vulnerabilities AS v
        WHERE v.ip = vulnerabilities.ip
          AND v.cveid = vulnerabilities.cveid
          AND v.port IS NOT NULL
    )
"""


class Shodan2DBError(Exception):
    """An error to report to the user (bad input file, invalid database...)."""


def log(verbose, message):
    if verbose:
        print(f"[+] {message}")


def db_path(database):
    """Database file path, with the .db extension added when missing."""
    database = str(database)
    return database if database.endswith(".db") else f"{database}.db"


@contextmanager
def open_database(database, *, create=False, verbose=False):
    """
    Yields a connection to an up-to-date database, migrating older schemas.
    The connection is in autocommit mode: callers open transactions explicitly.
    """
    path = db_path(database)
    if not create and not Path(path).is_file():
        raise Shodan2DBError(f"Database not found: {path}")

    conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        # WAL + NORMAL sync: much faster bulk inserts, still crash-safe
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        _ensure_schema(conn, verbose)
        yield conn
    except sqlite3.DatabaseError as e:
        raise Shodan2DBError(f"Database error ({path}): {e}") from e
    finally:
        conn.close()


@contextmanager
def _transaction(conn):
    conn.execute("BEGIN")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _ensure_schema(conn, verbose):
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == SCHEMA_VERSION:
        return
    if version > SCHEMA_VERSION:
        raise Shodan2DBError(
            f"Database schema version {version} is newer than this tool "
            f"supports ({SCHEMA_VERSION}); please upgrade Shodan2DB."
        )

    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    with _transaction(conn):
        if "services" in tables:
            log(verbose, f"Upgrading database schema to version {SCHEMA_VERSION}...")
            _rebuild_tables(conn, has_vulns="vulnerabilities" in tables)
        else:
            for statement in _TABLES:
                conn.execute(statement)
        for statement in _INDEXES_AND_VIEWS:
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _rebuild_tables(conn, has_vulns):
    """
    Copies version 0 tables into the current schema: ports become integers,
    duplicate banners are dropped (first one kept) and CVEs get a port column.
    """
    conn.execute("DROP VIEW IF EXISTS Summary")
    for index in (
        "ip_index",
        "nbvulns_index",
        "vulns_ip_index",
        "services_banner_index",
    ):
        conn.execute(f"DROP INDEX IF EXISTS {index}")

    conn.execute("ALTER TABLE services RENAME TO services_old")
    if has_vulns:
        conn.execute("ALTER TABLE vulnerabilities RENAME TO vulnerabilities_old")
    for statement in _TABLES:
        conn.execute(statement)

    columns = ", ".join(SERVICE_COLUMNS)
    select = ", ".join(
        "CAST(port AS INTEGER)" if c == "port" else c for c in SERVICE_COLUMNS
    )
    conn.execute(
        f"INSERT OR IGNORE INTO services ({columns}) "
        f"SELECT {select} FROM services_old ORDER BY id"
    )
    conn.execute("DROP TABLE services_old")

    if has_vulns:
        old_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities_old)")
        }
        port = "CAST(port AS INTEGER)" if "port" in old_columns else "NULL"
        conn.execute(
            "INSERT OR IGNORE INTO vulnerabilities "
            "(ip, port, cveid, verified, cvss, summary) "
            f"SELECT ip, {port}, cveid, verified, cvss, summary FROM vulnerabilities_old"
        )
        conn.execute("DROP TABLE vulnerabilities_old")


def init_database(database, verbose=False):
    """Creates the database, or migrates it to the current schema."""
    with open_database(database, create=True, verbose=verbose):
        pass


def _join(values):
    return " ".join(values) if values else None


def _service_row(banner):
    location = banner.get("location") or {}
    vulns = banner.get("vulns")
    values = {
        "ip": banner.get("ip_str"),
        "asn": banner.get("asn"),
        "hostnames": _join(banner.get("hostnames")),
        "domains": _join(banner.get("domains")),
        "org": banner.get("org"),
        "timestamp": banner.get("timestamp"),
        "isp": banner.get("isp"),
        "os": banner.get("os"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "transport": banner.get("transport"),
        "port": banner.get("port"),
        "data": banner.get("data"),
        "city": location.get("city"),
        "region_code": location.get("region_code"),
        "area_code": location.get("area_code"),
        "country_code": location.get("country_code"),
        "country_name": location.get("country_name"),
        "nbvulns": len(vulns) if vulns is not None else None,
        "tags": _join(banner.get("tags")),
    }
    return tuple(values[c] for c in SERVICE_COLUMNS)


def parse_file(inputfile, database, verbose=False):
    """
    Imports a Shodan JSON / JSON.GZ export (one banner per line) in a single
    transaction. Banners and CVEs already in the database are skipped.
    Returns counters of inserted rows and skipped lines.
    """
    inputfile = str(inputfile)
    opener = gzip.open if inputfile.endswith(".gz") else open
    stats = {"services": 0, "vulnerabilities": 0, "skipped_lines": 0}

    with open_database(database, create=True, verbose=verbose) as conn:
        log(verbose, f"Importing {inputfile}...")
        try:
            with opener(inputfile, "rt", encoding="utf-8") as lines, _transaction(conn):
                for line_no, line in enumerate(lines, 1):
                    if not line.strip():
                        continue
                    try:
                        banner = json.loads(line)
                    except json.JSONDecodeError:
                        banner = None
                    if not isinstance(banner, dict):
                        print(
                            f"[!] Skipping line {line_no}: invalid JSON",
                            file=sys.stderr,
                        )
                        stats["skipped_lines"] += 1
                        continue

                    row = _service_row(banner)
                    stats["services"] += conn.execute(_INSERT_SERVICE, row).rowcount

                    ip, port = banner.get("ip_str"), banner.get("port")
                    vulns = banner.get("vulns")
                    for cveid, vuln in vulns.items() if isinstance(vulns, dict) else ():
                        vuln = vuln if isinstance(vuln, dict) else {}
                        values = (
                            ip,
                            port,
                            cveid,
                            vuln.get("verified"),
                            vuln.get("cvss"),
                            vuln.get("summary"),
                        )
                        stats["vulnerabilities"] += conn.execute(
                            _INSERT_VULN, values
                        ).rowcount

                conn.execute(_DROP_SUPERSEDED_VULNS)
        except FileNotFoundError as e:
            raise Shodan2DBError(f"Input file not found: {inputfile}") from e
        except (OSError, EOFError, UnicodeDecodeError) as e:
            raise Shodan2DBError(f"Cannot read {inputfile}: {e}") from e

    log(
        verbose,
        f"Inserted {stats['services']} services and {stats['vulnerabilities']} "
        f"vulnerabilities ({stats['skipped_lines']} lines skipped)",
    )
    return stats

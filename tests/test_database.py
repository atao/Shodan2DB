import gzip
import json
import sqlite3

import pytest

from conftest import VULN, banner, rows, write_export
from shodan2db import Shodan2DBError, init_database, open_database, parse_file
from shodan2db.database import SCHEMA_VERSION


def test_vulns_are_attached_to_their_port(tmp_path, db):
    export = write_export(
        tmp_path / "in.json",
        [banner(80, {"CVE-2024-0001": VULN}), banner(443, {"CVE-2024-0001": VULN})],
    )
    parse_file(export, db)

    assert rows(db, "SELECT port, cveid FROM vulnerabilities ORDER BY port") == [
        (80, "CVE-2024-0001"),
        (443, "CVE-2024-0001"),
    ]


def test_ports_are_stored_as_integers(populated_db):
    assert rows(populated_db, "SELECT DISTINCT typeof(port) FROM services") == [
        ("integer",)
    ]


def test_reimporting_same_file_creates_no_duplicates(tmp_path, db):
    export = write_export(tmp_path / "in.json", [banner(80, {"CVE-2024-0001": VULN})])
    first = parse_file(export, db)
    second = parse_file(export, db)

    assert (first["services"], first["vulnerabilities"]) == (1, 1)
    assert (second["services"], second["vulnerabilities"]) == (0, 0)
    assert rows(db, "SELECT COUNT(*) FROM services") == [(1,)]


def test_new_scan_of_same_port_is_kept(tmp_path, db):
    export = write_export(
        tmp_path / "in.json",
        [banner(80), banner(80, timestamp="2026-02-01T00:00:00", data="changed")],
    )
    parse_file(export, db)

    assert rows(db, "SELECT COUNT(*) FROM services") == [(2,)]


def test_gzip_input(tmp_path, db):
    path = tmp_path / "in.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(json.dumps(banner(22)) + "\n")
    parse_file(path, db)

    assert rows(db, "SELECT port FROM services") == [(22,)]


def test_invalid_lines_are_skipped(tmp_path, db, capsys):
    export = write_export(
        tmp_path / "in.json", [banner(80)], extra_lines=["{not json", "[1, 2]", ""]
    )
    stats = parse_file(export, db)

    assert stats == {"services": 1, "vulnerabilities": 0, "skipped_lines": 2}
    assert "Skipping line 2" in capsys.readouterr().err


def test_unreadable_gzip_rolls_back(tmp_path, db):
    path = tmp_path / "broken.json.gz"
    path.write_bytes(b"not gzip at all")

    with pytest.raises(Shodan2DBError, match="Cannot read"):
        parse_file(path, db)
    assert rows(db, "SELECT COUNT(*) FROM services") == [(0,)]


def test_missing_database_is_an_error(tmp_path):
    with pytest.raises(Shodan2DBError, match="not found"):
        with open_database(tmp_path / "missing.db"):
            pass


def test_db_extension_is_added(tmp_path):
    init_database(tmp_path / "audit")
    assert (tmp_path / "audit.db").is_file()


def test_newer_schema_is_refused(db):
    init_database(db)
    conn = sqlite3.connect(db)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()

    with pytest.raises(Shodan2DBError, match="newer"):
        init_database(db)


def _legacy_database(db):
    """Schema of releases before user_version (port TEXT, CVEs per ip only)."""
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, "
        "asn TEXT, hostnames TEXT, domains TEXT, org TEXT, timestamp TEXT, isp TEXT, "
        "os TEXT, product TEXT, version TEXT, transport TEXT, port TEXT, data TEXT, "
        "city TEXT, region_code TEXT, area_code TEXT, country_code TEXT, "
        "country_name TEXT, nbvulns INTEGER, tags TEXT)"
    )
    conn.execute("CREATE INDEX ip_index ON services(ip)")
    conn.execute("CREATE VIEW Summary AS SELECT ip, port FROM services")
    for _ in range(2):
        conn.execute(
            "INSERT INTO services (ip, port, transport, timestamp) "
            "VALUES ('192.0.2.10', '80', 'tcp', '2026-01-01T00:00:00')"
        )
    conn.execute(
        "CREATE TABLE vulnerabilities (ip TEXT, cveid TEXT, verified NUMERIC, "
        "cvss REAL, summary TEXT, UNIQUE(ip, cveid) ON CONFLICT IGNORE)"
    )
    conn.execute(
        "INSERT INTO vulnerabilities VALUES ('192.0.2.10', 'CVE-2024-0001', 0, 9.8, 's')"
    )
    conn.commit()
    conn.close()


def test_legacy_schema_is_migrated(db):
    _legacy_database(db)
    init_database(db)

    assert rows(db, "PRAGMA user_version") == [(SCHEMA_VERSION,)]
    assert rows(db, "SELECT ip, port FROM services") == [("192.0.2.10", 80)]
    assert rows(db, "SELECT ip, port, cveid FROM vulnerabilities") == [
        ("192.0.2.10", None, "CVE-2024-0001")
    ]
    assert rows(db, "SELECT COUNT(*) FROM Summary") == [(1,)]


def test_reimport_replaces_migrated_cves_without_port(tmp_path, db):
    _legacy_database(db)
    export = write_export(tmp_path / "in.json", [banner(80, {"CVE-2024-0001": VULN})])
    parse_file(export, db)

    assert rows(db, "SELECT port, cveid FROM vulnerabilities") == [
        (80, "CVE-2024-0001")
    ]

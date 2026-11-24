import gzip
import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from shodan2db import Shodan2DB, cli

TEMPLATE = str(Path(__file__).resolve().parent.parent / "templates" / "report.html")

VULN = {"verified": False, "cvss": 9.8, "summary": "Bad bug"}


def banner(port, vulns=None, timestamp="2026-01-01T00:00:00", data="HTTP/1.1 200 OK"):
    return {
        "ip_str": "192.0.2.10",
        "port": port,
        "transport": "tcp",
        "timestamp": timestamp,
        "hostnames": ["www.example.com"],
        "domains": ["example.com"],
        "data": data,
        "location": {"city": "Paris", "country_code": "FR"},
        **({"vulns": vulns} if vulns else {}),
    }


def write_export(path, banners):
    path.write_text("\n".join(json.dumps(b) for b in banners) + "\n", encoding="utf-8")
    return str(path)


def parse(inputfile, database):
    Shodan2DB.init_database(verbose=False, database=database)
    Shodan2DB.parser(verbose=False, inputfile=inputfile, database=database)


def rows(database, query):
    with sqlite3.connect(database) as conn:
        return conn.execute(query).fetchall()


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "test.db")


def test_vulns_are_attached_to_their_port(tmp_path, db):
    export = write_export(
        tmp_path / "in.json",
        [banner(80, {"CVE-2024-0001": VULN}), banner(443, {"CVE-2024-0001": VULN})],
    )
    parse(export, db)

    assert rows(db, "SELECT port, cveid FROM vulnerabilities ORDER BY port") == [
        ("443", "CVE-2024-0001"),
        ("80", "CVE-2024-0001"),
    ]


def test_reimporting_same_file_creates_no_duplicates(tmp_path, db):
    export = write_export(tmp_path / "in.json", [banner(80, {"CVE-2024-0001": VULN})])
    parse(export, db)
    parse(export, db)

    assert rows(db, "SELECT COUNT(*) FROM services") == [(1,)]
    assert rows(db, "SELECT COUNT(*) FROM vulnerabilities") == [(1,)]


def test_new_scan_of_same_port_is_kept(tmp_path, db):
    export = write_export(
        tmp_path / "in.json",
        [banner(80), banner(80, timestamp="2026-02-01T00:00:00", data="changed")],
    )
    parse(export, db)

    assert rows(db, "SELECT COUNT(*) FROM services") == [(2,)]


def test_gzip_input(tmp_path, db):
    path = tmp_path / "in.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(json.dumps(banner(22)) + "\n")
    parse(str(path), db)

    assert rows(db, "SELECT port FROM services") == [("22",)]


def test_old_schema_is_migrated(tmp_path, db):
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, "
            "asn TEXT, hostnames TEXT, domains TEXT, org TEXT, timestamp TEXT, isp TEXT, "
            "os TEXT, product TEXT, version TEXT, transport TEXT, port TEXT, data TEXT, "
            "city TEXT, region_code TEXT, area_code TEXT, country_code TEXT, "
            "country_name TEXT, nbvulns INTEGER, tags TEXT)"
        )
        for _ in range(2):
            conn.execute(
                "INSERT INTO services (ip, port, transport, timestamp) "
                "VALUES ('192.0.2.10', '80', 'tcp', 't')"
            )
        conn.execute(
            "CREATE TABLE vulnerabilities (ip TEXT, cveid TEXT, verified NUMERIC, "
            "cvss REAL, summary TEXT, UNIQUE(ip, cveid) ON CONFLICT IGNORE)"
        )
        conn.execute(
            "INSERT INTO vulnerabilities VALUES ('192.0.2.10', 'CVE-1', 0, 5.0, 's')"
        )

    Shodan2DB.init_database(verbose=False, database=db)

    assert rows(db, "SELECT ip, port, cveid FROM vulnerabilities") == [
        ("192.0.2.10", None, "CVE-1")
    ]
    assert rows(db, "SELECT COUNT(*) FROM services") == [(1,)]


@pytest.fixture
def populated_db(tmp_path, db):
    export = write_export(
        tmp_path / "in.json",
        [banner(80, {"CVE-2024-0001": VULN}), banner(443, {"CVE-2024-0001": VULN})],
    )
    parse(export, db)
    return db


@pytest.mark.parametrize(
    "fmt, html, osint",
    [("html", True, False), ("osint", False, True), ("all", True, True)],
)
def test_export_format(tmp_path, populated_db, fmt, html, osint):
    html_path, json_path = tmp_path / "r.html", tmp_path / "o.json"
    result = CliRunner().invoke(
        cli,
        [
            "export",
            "-d", populated_db,
            "-t", TEMPLATE,
            "-f", fmt,
            "-o", str(html_path),
            "--osint-output", str(json_path),
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert html_path.exists() is html
    assert json_path.exists() is osint


def test_osint_counts_cve_once_per_host(tmp_path, populated_db):
    json_path = tmp_path / "o.json"
    CliRunner().invoke(
        cli,
        ["export", "-d", populated_db, "-f", "osint", "--osint-output", str(json_path)],
    )
    entities = json.loads(json_path.read_text())["entities"]
    ip = next(e for e in entities if e["value"] == "192.0.2.10")

    assert "Total CVEs: 1" in ip["comments"]


def test_html_report_shows_port_and_host_count(tmp_path, populated_db):
    html_path = tmp_path / "r.html"
    Shodan2DB.export(
        verbose=False, exportfile=str(html_path), database=populated_db,
        template_file=TEMPLATE,
    )  # fmt: skip
    html = html_path.read_text()

    assert "1 hosts affected" in html
    assert '<span class="tag is-light is-info">443</span>' in html

import json
import sqlite3

import pytest

from shodan2db import parse_file

VULN = {"verified": False, "cvss": 9.8, "summary": "Bad bug"}


def banner(port, vulns=None, ip="192.0.2.10", timestamp="2026-01-01T00:00:00", **extra):
    return {
        "ip_str": ip,
        "port": port,
        "transport": "tcp",
        "timestamp": timestamp,
        "hostnames": ["www.example.com"],
        "domains": ["example.com"],
        "isp": "Example ISP",
        "org": "Example Org",
        "product": "nginx",
        "version": "1.0",
        "data": "HTTP/1.1 200 OK\r\nServer: nginx",
        "location": {"city": "Paris", "country_code": "FR"},
        **({"vulns": vulns} if vulns else {}),
        **extra,
    }


def write_export(path, banners, extra_lines=()):
    lines = [json.dumps(b) for b in banners] + list(extra_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def rows(database, query):
    conn = sqlite3.connect(database)
    try:
        return conn.execute(query).fetchall()
    finally:
        conn.close()


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def populated_db(tmp_path, db):
    """Host .10 has the same CVE on 80 and 443; host .20 has no CVE."""
    export = write_export(
        tmp_path / "in.json",
        [
            banner(80, {"CVE-2024-0001": VULN}),
            banner(443, {"CVE-2024-0001": VULN, "CVE-2024-0002": {"cvss": 5.0}}),
            banner(22, ip="192.0.2.20", hostnames=[], domains=[]),
        ],
    )
    parse_file(export, db)
    return db

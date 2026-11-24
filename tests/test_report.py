import pytest

from shodan2db import Shodan2DBError, export_html, open_database
from shodan2db.report import load_report_data


def test_report_data_is_grouped_by_host(populated_db):
    with open_database(populated_db) as conn:
        data = load_report_data(conn)

    assert data["total_hosts"] == 2
    assert data["total_services"] == 3
    # CVE-2024-0001 on two ports counts once
    assert data["total_vulns"] == 2
    [vulnerable] = data["vulns_hosts"]
    assert vulnerable["ip"] == "192.0.2.10"
    assert vulnerable["nbvulns"] == 2
    assert [s["port"] for s in vulnerable["services"]] == [80, 443]
    assert [(v["cveid"], v["port"]) for v in vulnerable["vulns"]] == [
        ("CVE-2024-0001", 80),
        ("CVE-2024-0001", 443),
        ("CVE-2024-0002", 443),
    ]
    assert [h["ip"] for h in data["all_hosts"]] == ["192.0.2.20"]
    assert [(c["cveid"], c["count"]) for c in data["cves"]] == [
        ("CVE-2024-0001", 1),
        ("CVE-2024-0002", 1),
    ]


def test_html_report(tmp_path, populated_db):
    output = export_html(populated_db, tmp_path / "report")
    html = (tmp_path / "report.html").read_text()

    assert output.endswith("report.html")
    assert "1 hosts affected" in html
    assert '<span class="tag is-light is-info">443</span>' in html
    assert "192.0.2.20" in html
    assert "unpkg.com" not in html


def test_report_escapes_banner_content(tmp_path, db):
    from conftest import banner, write_export
    from shodan2db import parse_file

    export = write_export(tmp_path / "in.json", [banner(80, data="<script>x</script>")])
    parse_file(export, db)
    html = tmp_path / "r.html"
    export_html(db, html)

    assert "<script>x</script>" not in html.read_text()


def test_template_error_is_reported(tmp_path, populated_db):
    template = tmp_path / "bad.html"
    template.write_text("{% for %}")

    with pytest.raises(Shodan2DBError, match="Template error"):
        export_html(populated_db, tmp_path / "r.html", template)


def test_host_names_and_tags_merge_all_banners(tmp_path, db):
    from conftest import banner, write_export
    from shodan2db import parse_file

    export = write_export(
        tmp_path / "in.json",
        [
            banner(80, hostnames=["a.example.com", "a.example.com"], tags=["cdn"]),
            banner(443, hostnames=["a.example.com", "b.example.com"], tags=["eol"]),
        ],
    )
    parse_file(export, db)
    with open_database(db) as conn:
        [host] = load_report_data(conn)["all_hosts"]

    assert host["hostnames"] == "a.example.com b.example.com"
    assert host["tags"] == "cdn eol"

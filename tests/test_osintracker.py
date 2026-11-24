import json

import pytest

from conftest import banner, write_export
from shodan2db import OsintrackerExporter, export_osintracker, parse_file
from shodan2db.osintracker import ENTITY_TYPES, color_for_cvss, node_size_for_vulns


def by_value(graph):
    return {e["value"]: e for e in graph["entities"]}


def labels(graph):
    ids = {e["id"]: e["value"] for e in graph["entities"]}
    return sorted(
        (ids[r["originId"]], r["label"], ids[r["targetId"]]) for r in graph["relations"]
    )


@pytest.mark.parametrize(
    "cvss, color", [(9.8, "1"), (9.0, "1"), (7.5, "2"), (4.0, "3"), (2.0, "4")]
)
def test_color_for_cvss(cvss, color):
    assert color_for_cvss(cvss) == color


@pytest.mark.parametrize("count, size", [(0, "S"), (2, "S"), (3, "M"), (10, "L")])
def test_node_size(count, size):
    assert node_size_for_vulns(count) == size


def test_ip_entity_aggregates_all_services(populated_db):
    graph = OsintrackerExporter(populated_db).build()
    ip = by_value(graph)["192.0.2.10"]

    assert ip["typeId"] == ENTITY_TYPES["ip"]
    assert ip["countryCode"] == "FR"
    assert ip["colorNum"] == "1"
    assert "Ports: 80, 443" in ip["comments"]
    assert "CVEs: CVE-2024-0001, CVE-2024-0002" in ip["comments"]
    assert "Total CVEs: 2" in ip["comments"]


def test_host_without_cve(populated_db):
    ip = by_value(OsintrackerExporter(populated_db).build())["192.0.2.20"]

    assert ip["colorNum"] == "5"
    assert "critical" not in ip


def test_relations_and_alias(populated_db):
    graph = OsintrackerExporter(populated_db, alias="Campaign").build()

    assert labels(graph) == [
        ("192.0.2.10", "hosts", "example.com"),
        ("192.0.2.10", "resolves to", "www.example.com"),
        ("Campaign", "contains", "192.0.2.10"),
        ("Campaign", "contains", "192.0.2.20"),
    ]


def test_name_listed_as_hostname_and_domain_is_one_entity(tmp_path, db):
    export = write_export(
        tmp_path / "in.json",
        [
            banner(80, hostnames=["example.com"], domains=["example.com"]),
            banner(80, ip="192.0.2.11", hostnames=["example.com"], domains=[]),
        ],
    )
    parse_file(export, db)
    graph = OsintrackerExporter(db).build()

    names = [e for e in graph["entities"] if e["value"] == "example.com"]
    assert len(names) == 1
    assert names[0]["comments"] == "IPs: 192.0.2.10, 192.0.2.11"
    assert labels(graph) == [
        ("192.0.2.10", "resolves to", "example.com"),
        ("192.0.2.11", "resolves to", "example.com"),
    ]


def test_export_writes_json(tmp_path, populated_db):
    output = export_osintracker(populated_db, tmp_path / "graph", alias="X")
    graph = json.loads((tmp_path / "graph.json").read_text())

    assert output.endswith("graph.json")
    assert len(graph["entities"]) == 5  # alias + 2 IPs + 2 names
    assert len({e["id"] for e in graph["entities"]}) == 5

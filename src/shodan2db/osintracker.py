"""
Export Shodan2DB assets to osintracker JSON format: one entity per IP and per
host/domain name, linked by relations (and to an optional central alias).

Format reference: https://wiki.osintracker.com/data/import-export
"""

import json
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .database import Shodan2DBError, log, open_database

# Entity type IDs from the osintracker instance
ENTITY_TYPES = {
    "ip": "clh6sgxq9tww10buuhzho55jg",  # Internet > IP
    "name": "clh6sdulhtz2s0buj08lo5r40",  # Internet > domain name (hostnames too)
    "alias": "clh6r8n9rtvg30bt9jnrlybmt",  # Alias/Campaign central hub entity
}


def color_for_cvss(max_cvss: float) -> str:
    if max_cvss >= 9.0:
        return "1"  # Red
    if max_cvss >= 7.0:
        return "2"  # Orange
    if max_cvss >= 4.0:
        return "3"  # Yellow
    return "4"  # Green


def node_size_for_vulns(vuln_count: int) -> str:
    if vuln_count >= 10:
        return "L"
    if vuln_count >= 3:
        return "M"
    return "S"


def _add_unique(items: list, value) -> None:
    if value and value not in items:
        items.append(value)


def load_hosts(conn) -> dict[str, dict[str, Any]]:
    """Aggregates every service and CVE of each IP (two queries in total)."""
    hosts: dict[str, dict[str, Any]] = {}
    for row in conn.execute("""
        SELECT ip, hostnames, domains, port, product, version, isp, org, country_code
        FROM services
        WHERE ip IS NOT NULL
        ORDER BY ip, port
    """):
        host = hosts.setdefault(
            row["ip"],
            {
                "names": {},  # name -> relation label
                "ports": [],
                "products": [],
                "isp": None,
                "org": None,
                "country_code": None,
                "cves": [],
                "max_cvss": 0.0,
            },
        )
        # A name listed both as hostname and domain is a single entity
        for name in (row["hostnames"] or "").split():
            host["names"][name] = "resolves to"
        for name in (row["domains"] or "").split():
            host["names"].setdefault(name, "hosts")
        _add_unique(host["ports"], row["port"])
        product = " ".join(p for p in (row["product"], row["version"]) if p)
        _add_unique(host["products"], product)
        for field in ("isp", "org", "country_code"):
            host[field] = host[field] or row[field]

    for row in conn.execute("""
        SELECT ip, cveid, MAX(cvss) AS cvss
        FROM vulnerabilities
        GROUP BY ip, cveid
        ORDER BY ip, cvss IS NULL, cvss DESC
    """):
        host = hosts.get(row["ip"])
        if host is None:
            continue
        host["cves"].append(row["cveid"])
        host["max_cvss"] = max(host["max_cvss"], row["cvss"] or 0.0)
    return hosts


class OsintrackerExporter:
    """Builds the osintracker graph from a Shodan2DB database."""

    def __init__(
        self, database: str, verbose: bool = False, alias: Optional[str] = None
    ):
        self.database = database
        self.verbose = verbose
        self.alias = alias

    def build(self) -> dict[str, list]:
        with open_database(self.database, verbose=self.verbose) as conn:
            hosts = load_hosts(conn)
        log(self.verbose, f"Building osintracker graph for {len(hosts)} hosts...")

        now = int(time.time() * 1000)
        ids: dict[tuple[str, str], str] = {}
        entities: list[dict[str, Any]] = []
        relations: list[dict[str, Any]] = []

        def add_entity(kind, value, comments, cves=(), max_cvss=0.0, country=None):
            ids[kind, value] = str(uuid.uuid4())
            entity = {
                "id": ids[kind, value],
                "typeId": ENTITY_TYPES[kind],
                "value": value,
                "colorNum": color_for_cvss(max_cvss) if cves else "5",
                "nodeSize": node_size_for_vulns(len(cves)),
                "creationDate": now,
            }
            if country:
                entity["countryCode"] = country
            if cves:
                comments = [
                    *comments,
                    f"CVEs: {', '.join(cves)}",
                    f"Total CVEs: {len(cves)}",
                ]
                entity["critical"] = len(cves) >= 5
                entity["progress"] = "exclamation" if len(cves) >= 3 else "question"
                entity["rating"] = str(min(3, len(cves) // 2))
            if comments:
                entity["comments"] = "\n".join(comments)
            entities.append(entity)

        def add_relation(origin, target, label):
            relations.append(
                {
                    "id": str(uuid.uuid4()),
                    "originId": ids[origin],
                    "targetId": ids[target],
                    "label": label,
                    "creationDate": now,
                }
            )

        if self.alias:
            add_entity("alias", self.alias, [])

        # Names can point to several IPs: aggregate their CVEs
        names: dict[str, dict[str, Any]] = {}
        for ip, host in hosts.items():
            comments = []
            if host["ports"]:
                comments.append(f"Ports: {', '.join(map(str, host['ports']))}")
            if host["products"]:
                comments.append(f"Products: {', '.join(host['products'])}")
            if host["isp"]:
                comments.append(f"ISP: {host['isp']}")
            if host["org"]:
                comments.append(f"Organization: {host['org']}")
            add_entity(
                "ip", ip, comments, host["cves"], host["max_cvss"], host["country_code"]
            )
            if self.alias:
                add_relation(("alias", self.alias), ("ip", ip), "contains")

            for name in host["names"]:
                entry = names.setdefault(name, {"ips": [], "cves": [], "max_cvss": 0.0})
                entry["ips"].append(ip)
                for cve in host["cves"]:
                    _add_unique(entry["cves"], cve)
                entry["max_cvss"] = max(entry["max_cvss"], host["max_cvss"])

        for name, entry in names.items():
            add_entity(
                "name", name, [f"IPs: {', '.join(entry['ips'])}"],
                entry["cves"], entry["max_cvss"],
            )  # fmt: skip
        for ip, host in hosts.items():
            for name, label in host["names"].items():
                add_relation(("ip", ip), ("name", name), label)

        return {"entities": entities, "relations": relations}

    def export_to_json(self, output_file: str) -> str:
        """Writes the osintracker JSON file and returns its path."""
        output_file = str(output_file)
        if not output_file.endswith(".json"):
            output_file = f"{output_file}.json"

        graph = self.build()
        try:
            Path(output_file).write_text(
                json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError as e:
            raise Shodan2DBError(f"Cannot write {output_file}: {e}") from e

        log(
            self.verbose,
            f"Exported {len(graph['entities'])} entities and "
            f"{len(graph['relations'])} relations to {output_file}",
        )
        return output_file


def export_osintracker(database, output_file, alias=None, verbose=False):
    return OsintrackerExporter(database, verbose, alias).export_to_json(output_file)

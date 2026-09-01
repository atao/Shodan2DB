#!/usr/bin/env python3
"""
Export assets from Shodan2DB SQLite database to osinttracker JSON format.
Creates entities (IPs, domains, hostnames) and relationships between them.

Format reference: https://wiki.osintracker.com/data/import-export
"""

import json
import sqlite3
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import click


class OsintTrackerExporter:
    """Handles exporting Shodan2DB data to osinttracker JSON format."""

    # Entity type IDs from osinttracker instance
    ENTITY_TYPES = {
        "ip": "clh6sgxq9tww10buuhzho55jg",  # Internet > IP
        "hostname": "clh6sdulhtz2s0buj08lo5r40",  # Internet > domain name (or create Hostname type)
        "domain": "clh6sdulhtz2s0buj08lo5r40",  # Internet > domain name
        "alias": "clh6r8n9rtvg30bt9jnrlybmt",  # Alias/Campaign central hub entity
    }

    def __init__(
        self, database: str, verbose: bool = False, alias: Optional[str] = None
    ):
        """Initialize the exporter with database connection parameters."""
        self.database = database
        self.verbose = verbose
        self.alias = alias

        # Ensure database file has correct extension
        if not self.database.endswith(".db"):
            self.database = f"{self.database}.db"

        # Verify database exists
        if not Path(self.database).exists():
            raise FileNotFoundError(f"Database file not found: {self.database}")

        # Cache for entity IDs to avoid duplicates
        self.entity_ids: Dict[Tuple[str, str], str] = {}
        self.relationships: Set[Tuple[str, str, str, str]] = set()

    def _log(self, message: str, level: str = "info") -> None:
        """Print verbose log messages."""
        if self.verbose:
            prefix = {
                "info": "[+]",
                "warning": "[!]",
                "error": "[-]",
            }.get(level, "[*]")
            print(f"{prefix} {message}")

    def _get_entity_id(self, entity_type: str, value: str) -> str:
        """Get or create unique entity ID."""
        key = (entity_type, value)
        if key not in self.entity_ids:
            self.entity_ids[key] = str(uuid.uuid4())
        return self.entity_ids[key]

    def _get_vulnerabilities(
        self, conn: sqlite3.Connection, ip: str
    ) -> Tuple[int, List[str]]:
        """Fetch vulnerabilities for a given IP address."""
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT cveid, cvss FROM vulnerabilities 
            WHERE ip = ? 
            ORDER BY cvss DESC NULLS LAST
            """,
            (ip,),
        )
        cve_list = []
        max_cvss = 0.0
        for row in cursor.fetchall():
            cve_list.append(row[0])
            if row[1] is not None and row[1] > max_cvss:
                max_cvss = row[1]
        return len(cve_list), cve_list

    def _parse_list_field(self, field_value: Optional[str]) -> List[str]:
        """Convert space-separated string to list, handling None values."""
        if not field_value:
            return []
        return [v.strip() for v in field_value.split() if v.strip()]

    def _get_color_for_cvss(self, max_cvss: float) -> str:
        """Determine color based on CVSS score."""
        if max_cvss >= 9.0:
            return "1"  # Red
        elif max_cvss >= 7.0:
            return "2"  # Orange
        elif max_cvss >= 4.0:
            return "3"  # Yellow
        else:
            return "4"  # Green

    def _get_node_size_for_vulns(self, vuln_count: int) -> str:
        """Determine node size based on vulnerability count."""
        if vuln_count >= 10:
            return "L"
        elif vuln_count >= 3:
            return "M"
        else:
            return "S"

    def _create_entity(
        self,
        entity_type: str,
        value: str,
        service_data: Dict[str, Any],
        vuln_count: int,
        cve_ids: List[str],
    ) -> Dict[str, Any]:
        """Create an osinttracker entity."""
        entity_id = self._get_entity_id(entity_type, value)

        # Determine max CVSS for color coding
        max_cvss = 0.0
        if cve_ids:
            conn = sqlite3.connect(self.database)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT MAX(cvss) FROM vulnerabilities WHERE cveid IN ("
                + ",".join("?" * len(cve_ids))
                + ")",
                cve_ids,
            )
            result = cursor.fetchone()
            if result[0] is not None:
                max_cvss = result[0]
            conn.close()

        # Build comments
        comments_parts = []
        if service_data.get("product"):
            comments_parts.append(f"Product: {service_data['product']}")
        if service_data.get("version"):
            comments_parts.append(f"Version: {service_data['version']}")
        if service_data.get("port"):
            comments_parts.append(f"Port: {service_data['port']}")
        if service_data.get("isp"):
            comments_parts.append(f"ISP: {service_data['isp']}")
        if service_data.get("org"):
            comments_parts.append(f"Organization: {service_data['org']}")
        if cve_ids:
            comments_parts.append(f"CVEs: {', '.join(cve_ids)}")
            comments_parts.append(f"Total CVEs: {len(cve_ids)}")

        entity = {
            "id": entity_id,
            "typeId": self.ENTITY_TYPES.get(entity_type, "entity-type-unknown"),
            "value": value,
            "colorNum": self._get_color_for_cvss(max_cvss) if vuln_count > 0 else "5",
            "nodeSize": self._get_node_size_for_vulns(vuln_count),
            "creationDate": int(datetime.now().timestamp() * 1000),
        }

        # Add optional fields
        if service_data.get("country_code"):
            entity["countryCode"] = service_data["country_code"]

        if comments_parts:
            entity["comments"] = "\n".join(comments_parts)

        if vuln_count > 0:
            entity["critical"] = vuln_count >= 5
            entity["progress"] = "exclamation" if vuln_count >= 3 else "question"
            entity["rating"] = str(min(3, vuln_count // 2))

        return entity

    def _add_relationship(
        self,
        origin_type: str,
        origin_value: str,
        target_type: str,
        target_value: str,
        label: str,
    ) -> str:
        """Add a relationship between two entities."""
        origin_id = self._get_entity_id(origin_type, origin_value)
        target_id = self._get_entity_id(target_type, target_value)

        # Avoid duplicate relationships
        rel_key = (origin_id, target_id, label, "forward")
        self.relationships.add(rel_key)

        return str(uuid.uuid4())

    def export_to_json(self, output_file: str) -> None:
        """Export all assets to osinttracker JSON format."""
        if not output_file.endswith(".json"):
            output_file = f"{output_file}.json"

        self._log(f"Exporting to osinttracker format: {output_file}...")

        try:
            with sqlite3.connect(self.database) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Fetch all unique services
                cursor.execute("SELECT * FROM summary")
                services = cursor.fetchall()

                entities = []
                entity_set: Set[Tuple[str, str]] = set()
                alias_id = None

                # Create alias/campaign entity if provided
                if self.alias:
                    alias_entity = self._create_entity("alias", self.alias, {}, 0, [])
                    entities.append(alias_entity)
                    entity_set.add(("alias", self.alias))
                    alias_id = self._get_entity_id("alias", self.alias)
                    self._log(f"Created alias entity: {self.alias}")

                self._log(f"Processing {len(services)} services...")

                # Process each service record
                for service in services:
                    service_dict = dict(service)
                    ip = service_dict.get("ip")
                    hostnames = self._parse_list_field(service_dict.get("hostnames"))
                    domains = self._parse_list_field(service_dict.get("domains"))

                    # Get vulnerabilities for this IP
                    vuln_count, cve_ids = self._get_vulnerabilities(conn, ip)

                    # Create IP entity
                    if ip:
                        entity_key = ("ip", ip)
                        if entity_key not in entity_set:
                            entity_set.add(entity_key)
                            entity = self._create_entity(
                                "ip", ip, service_dict, vuln_count, cve_ids
                            )
                            entities.append(entity)

                            # Create relationship to alias if provided
                            if alias_id:
                                self._add_relationship(
                                    "alias", self.alias, "ip", ip, "contains"
                                )

                    # Create hostname entities and relationships
                    for hostname in hostnames:
                        if hostname:
                            entity_key = ("hostname", hostname)
                            if entity_key not in entity_set:
                                entity_set.add(entity_key)
                                entity = self._create_entity(
                                    "hostname",
                                    hostname,
                                    service_dict,
                                    vuln_count,
                                    cve_ids,
                                )
                                entities.append(entity)

                            # Create relationship IP -> Hostname
                            if ip:
                                self._add_relationship(
                                    "ip", ip, "hostname", hostname, "resolves to"
                                )

                    # Create domain entities and relationships
                    for domain in domains:
                        if domain:
                            entity_key = ("domain", domain)
                            if entity_key not in entity_set:
                                entity_set.add(entity_key)
                                entity = self._create_entity(
                                    "domain", domain, service_dict, vuln_count, cve_ids
                                )
                                entities.append(entity)

                            # Create relationship IP -> Domain
                            if ip:
                                self._add_relationship(
                                    "ip", ip, "domain", domain, "hosts"
                                )

                # Build relationships array
                relations = []
                for origin_id, target_id, label, direction in self.relationships:
                    relation = {
                        "id": str(uuid.uuid4()),
                        "originId": origin_id,
                        "targetId": target_id,
                        "label": label,
                        "creationDate": int(datetime.now().timestamp() * 1000),
                    }
                    relations.append(relation)

                # Build final structure
                output_data = {
                    "entities": entities,
                    "relations": relations,
                }

                # Write JSON
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(output_data, f, ensure_ascii=False, indent=2)

                self._log(
                    f"Successfully exported {len(entities)} entities "
                    f"and {len(relations)} relationships"
                )

        except sqlite3.Error as e:
            print(f"[-] Database error: {e}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"[-] File error: {e}", file=sys.stderr)
            sys.exit(1)


# Standalone CLI support (for backward compatibility)
if __name__ == "__main__":

    @click.command()
    @click.option(
        "-d",
        "--database",
        default="shodan.db",
        help="Path to SQLite database file (default: shodan.db)",
    )
    @click.option(
        "-o",
        "--output",
        default="assets_osinttracker.json",
        help="Output JSON file path (default: assets_osinttracker.json)",
    )
    @click.option(
        "-a",
        "--alias",
        default=None,
        help="Create a central alias/campaign entity linked to all assets",
    )
    @click.option(
        "-v",
        "--verbose",
        is_flag=True,
        help="Enable verbose output",
    )
    def main(database: str, output: str, alias: Optional[str], verbose: bool) -> None:
        """
        Export Shodan2DB assets to osinttracker JSON format.

        Generates entities (IPs, hostnames, domains) with relationships.
        Compatible with osinttracker import/export format.
        """
        try:
            exporter = OsintTrackerExporter(database, verbose, alias)
            exporter.export_to_json(output)
            print(f"[✓] Export completed successfully!")

        except FileNotFoundError as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error: {e}", file=sys.stderr)
            sys.exit(1)

    main()

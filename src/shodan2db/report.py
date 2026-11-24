"""HTML report rendering."""

import ipaddress
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateError, select_autoescape

from . import __version__
from .database import Shodan2DBError, log, merge_words, open_database

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
BUILTIN_TEMPLATES = {
    "classic": TEMPLATES_DIR / "report.html",
    "modern": TEMPLATES_DIR / "modern.html",
}
DEFAULT_TEMPLATE = BUILTIN_TEMPLATES["classic"]

# Most to least severe; "none" is a host without any known CVE
SEVERITIES = ("critical", "high", "medium", "low", "unknown", "none")


def severity(cvss):
    """CVSS v3 qualitative rating ("unknown" when the score is missing)."""
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def resolve_template(template):
    """Accepts a built-in template name (classic, modern) or a file path."""
    if isinstance(template, str) and template in BUILTIN_TEMPLATES:
        return BUILTIN_TEMPLATES[template]
    path = Path(template)
    if not path.is_file():
        names = ", ".join(BUILTIN_TEMPLATES)
        raise Shodan2DBError(f"Template not found: {template} (built-in: {names})")
    return path


def _ip_sort_key(ip):
    try:
        address = ipaddress.ip_address(ip)
        return (address.version, int(address), ip)
    except ValueError:
        return (99, 0, ip)


def _group_cves(vulns):
    """One entry per CVE with every port it was reported on."""
    cves = {}
    for vuln in vulns:
        cve = cves.setdefault(
            vuln["cveid"],
            {
                "cveid": vuln["cveid"],
                "cvss": vuln["cvss"],
                "severity": severity(vuln["cvss"]),
                "summary": vuln["summary"],
                "verified": bool(vuln["verified"]),
                "ports": [],
            },
        )
        if vuln["port"] is not None and vuln["port"] not in cve["ports"]:
            cve["ports"].append(vuln["port"])
        cve["verified"] = cve["verified"] or bool(vuln["verified"])
    for cve in cves.values():
        cve["ports"].sort()
    return list(cves.values())


def load_report_data(conn):
    """
    Builds the template context. Services and CVEs are grouped by host here,
    so the template renders in linear time whatever the export size.
    """
    hosts = {}
    for row in conn.execute("""
        SELECT ip, hostnames, isp, org, city, country_name, tags
        FROM services
        WHERE ip IS NOT NULL
        ORDER BY ip, port
    """):
        host = hosts.setdefault(
            row["ip"],
            {
                "ip": row["ip"],
                "hostnames": None,
                "isp": None,
                "org": None,
                "city": None,
                "country": None,
                "tags": None,
                "services": [],
                "vulns": [],
                "nbvulns": 0,
            },
        )
        # Each banner may list different names/tags: keep them all
        host["hostnames"] = merge_words(host["hostnames"], row["hostnames"])
        host["tags"] = merge_words(host["tags"], row["tags"])
        for field, column in (
            ("isp", "isp"),
            ("org", "org"),
            ("city", "city"),
            ("country", "country_name"),
        ):
            host[field] = host[field] or row[column]

    total_services = 0
    for row in conn.execute("""
        SELECT DISTINCT ip, port, product, version, transport, data
        FROM services
        WHERE ip IS NOT NULL
        ORDER BY ip, port
    """):
        hosts[row["ip"]]["services"].append(row)
        total_services += 1

    for row in conn.execute("""
        SELECT ip, port, cveid, cvss, summary, verified
        FROM vulnerabilities
        ORDER BY ip, cvss DESC, port
    """):
        host = hosts.get(row["ip"])
        if host is not None:
            host["vulns"].append(row)

    severity_counts = dict.fromkeys(SEVERITIES[:-1], 0)
    for host in hosts.values():
        host["cves"] = _group_cves(host["vulns"])
        # The same CVE on several ports counts once for the host
        host["nbvulns"] = len(host["cves"])
        scores = [c["cvss"] for c in host["cves"] if c["cvss"] is not None]
        host["max_cvss"] = max(scores, default=None)
        host["severity"] = (
            "none"
            if not host["cves"]
            else min((c["severity"] for c in host["cves"]), key=SEVERITIES.index)
        )
        # Every severity present on the host: a host with critical and low
        # CVEs must show up when filtering on "low" too
        host["severities"] = [
            s for s in SEVERITIES[:-1] if any(c["severity"] == s for c in host["cves"])
        ] or ["none"]
        host["ports"] = sorted(
            {s["port"] for s in host["services"] if s["port"] is not None}
        )
        products = (
            " ".join(p for p in (s["product"], s["version"]) if p)
            for s in host["services"]
        )
        host["products"] = list(dict.fromkeys(p for p in products if p))
        for cve in host["cves"]:
            severity_counts[cve["severity"]] += 1

    cves = [
        {**dict(row), "severity": severity(row["cvss"])}
        for row in conn.execute("""
            SELECT cveid, COUNT(DISTINCT ip) AS count, MAX(cvss) AS cvss,
                   MAX(summary) AS summary
            FROM vulnerabilities
            GROUP BY cveid
            ORDER BY count DESC, cvss DESC
        """)
    ]

    ordered = sorted(hosts.values(), key=lambda h: _ip_sort_key(h["ip"]))
    by_risk = sorted(
        ordered,
        key=lambda h: (
            SEVERITIES.index(h["severity"]),
            -(h["max_cvss"] or 0),
            -h["nbvulns"],
        ),
    )
    vulnerable = [h for h in by_risk if h["nbvulns"]]
    return {
        # Hosts sorted by risk (most severe first), then by IP
        "hosts": by_risk,
        "vulns_hosts": vulnerable,
        "all_hosts": [h for h in ordered if not h["nbvulns"]],
        "total_hosts": len(hosts),
        "total_services": total_services,
        "total_vulns": sum(h["nbvulns"] for h in vulnerable),
        "severity_counts": severity_counts,
        # Number of hosts having at least one CVE of each severity
        "severity_host_counts": {
            s: sum(1 for h in hosts.values() if s in h["severities"])
            for s in SEVERITIES
        },
        "cves": cves,
    }


def export_html(database, output, template=DEFAULT_TEMPLATE, verbose=False):
    """Renders the HTML report and returns the path written."""
    output = str(output)
    if not output.endswith(".html"):
        output = f"{output}.html"
    template = resolve_template(template)

    with open_database(database, verbose=verbose) as conn:
        log(verbose, "Loading report data...")
        data = load_report_data(conn)
    data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    data["version"] = __version__

    log(verbose, f"Rendering {template.name}...")
    environment = Environment(
        loader=FileSystemLoader(str(template.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    try:
        content = environment.get_template(template.name).render(**data)
    except TemplateError as e:
        raise Shodan2DBError(f"Template error ({template}): {e}") from e

    try:
        Path(output).write_text(content, encoding="utf-8")
    except OSError as e:
        raise Shodan2DBError(f"Cannot write report {output}: {e}") from e

    log(verbose, f"Wrote report: {output}")
    return output

"""HTML report rendering."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateError, select_autoescape

from .database import Shodan2DBError, log, open_database

DEFAULT_TEMPLATE = Path(__file__).resolve().parent / "templates" / "report.html"


def load_report_data(conn):
    """
    Builds the template context. Services and CVEs are grouped by host here,
    so the template renders in linear time whatever the export size.
    """
    hosts = {}
    for row in conn.execute("""
        SELECT ip, MAX(hostnames) AS hostnames, MAX(isp) AS isp,
               MAX(city) AS city, MAX(tags) AS tags
        FROM services
        WHERE ip IS NOT NULL
        GROUP BY ip
        ORDER BY ip
    """):
        hosts[row["ip"]] = {**dict(row), "services": [], "vulns": [], "nbvulns": 0}

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
        SELECT ip, port, cveid, cvss, summary
        FROM vulnerabilities
        ORDER BY ip, cvss DESC, port
    """):
        host = hosts.get(row["ip"])
        if host is not None:
            host["vulns"].append(row)

    for host in hosts.values():
        # The same CVE on several ports counts once for the host
        host["nbvulns"] = len({vuln["cveid"] for vuln in host["vulns"]})

    cves = conn.execute("""
        SELECT cveid, COUNT(DISTINCT ip) AS count, MAX(cvss) AS cvss,
               MAX(summary) AS summary
        FROM vulnerabilities
        GROUP BY cveid
        ORDER BY count DESC, cvss DESC
    """).fetchall()

    vulnerable = sorted(
        (h for h in hosts.values() if h["nbvulns"]), key=lambda h: -h["nbvulns"]
    )
    return {
        "vulns_hosts": vulnerable,
        "all_hosts": [h for h in hosts.values() if not h["nbvulns"]],
        "total_hosts": len(hosts),
        "total_services": total_services,
        "total_vulns": sum(h["nbvulns"] for h in vulnerable),
        "cves": cves,
    }


def export_html(database, output, template=DEFAULT_TEMPLATE, verbose=False):
    """Renders the HTML report and returns the path written."""
    output = str(output)
    if not output.endswith(".html"):
        output = f"{output}.html"
    template = Path(template)

    with open_database(database, verbose=verbose) as conn:
        log(verbose, "Loading report data...")
        data = load_report_data(conn)

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

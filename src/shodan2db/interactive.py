"""
Interactive mode: pick Shodan exports, a database and the reports to build
from menus instead of command-line options.
"""

import gzip
import sqlite3
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

import click
import questionary
from questionary import Choice, Separator

from .database import db_path, parse_file
from .osintracker import export_osintracker
from .report import export_html

OTHER = "__other__"
NEW = "__new__"
_SKIPPED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "site-packages",
}


class Aborted(Exception):
    """The user cancelled a prompt (Ctrl-C)."""


@dataclass
class Plan:
    exports: list[Path] = field(default_factory=list)
    database: Path | None = None
    html: Path | None = None
    template: str = "modern"
    osint: Path | None = None
    alias: str | None = None


# --- Discovery -------------------------------------------------------------


def _walk(directory: Path, max_depth: int):
    """Files under directory, skipping hidden/virtualenv folders."""
    stack = [(directory, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if depth < max_depth and entry.name not in _SKIPPED_DIRS:
                    if not entry.name.startswith("."):
                        stack.append((entry, depth + 1))
            elif entry.is_file():
                yield entry


def _by_recency(paths):
    return sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)


def looks_like_shodan_export(path: Path) -> bool:
    """A Shodan export is JSON lines whose banners carry an "ip_str" field."""
    opener = gzip.open if path.name.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    return '"ip_str"' in line[:1_000_000]
    except (OSError, EOFError):
        pass
    return False


def discover_exports(directory: Path, max_depth: int = 2) -> list[Path]:
    candidates = (
        p for p in _walk(directory, max_depth) if p.name.endswith((".json", ".json.gz"))
    )
    return _by_recency(p for p in candidates if looks_like_shodan_export(p))


def _is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def discover_databases(directory: Path, max_depth: int = 2) -> list[Path]:
    return _by_recency(
        p for p in _walk(directory, max_depth) if p.suffix == ".db" and _is_sqlite(p)
    )


def describe_database(path: Path) -> str:
    """Short content summary, read-only (no migration, no file creation)."""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            hosts = conn.execute("SELECT COUNT(DISTINCT ip) FROM services").fetchone()[
                0
            ]
            cves = conn.execute(
                "SELECT COUNT(DISTINCT cveid) FROM vulnerabilities"
            ).fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return "not a Shodan2DB database"
    return f"{hosts} hosts, {cves} CVEs"


# --- Formatting helpers ----------------------------------------------------


def _size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _display(path: Path, directory: Path) -> str:
    try:
        return str(path.relative_to(directory))
    except ValueError:
        return str(path)


def _resolve(answer: str, directory: Path) -> Path:
    path = Path(answer).expanduser()
    return path if path.is_absolute() else directory / path


# --- Prompts -----------------------------------------------------------------


def _ask(question):
    answer = question.ask()
    if answer is None:  # questionary returns None on Ctrl-C
        raise Aborted
    return answer


def _validate_export(answer: str):
    path = Path(answer).expanduser()
    if not path.is_file():
        return "File not found"
    if not path.name.endswith((".json", ".json.gz")):
        return "Expected a .json or .json.gz file"
    return True


def _validate_file(answer: str):
    return Path(answer).expanduser().is_file() or "File not found"


def _not_empty(answer: str):
    return bool(answer.strip()) or "Required"


def _choose_exports(ui, directory: Path) -> list[Path]:
    found = discover_exports(directory)
    if found:
        choices = [
            Choice(
                f"{_display(p, directory)}  ({_size(p.stat().st_size)}, "
                f"{datetime.fromtimestamp(p.stat().st_mtime):%Y-%m-%d %H:%M})",
                str(p),
                checked=(i == 0),
            )
            for i, p in enumerate(found)
        ]
        choices += [Separator(), Choice("Another file…", OTHER)]
        selected = _ask(
            ui.checkbox(
                "Shodan exports to import (space: select, enter: confirm)",
                choices=choices,
                validate=lambda s: bool(s) or "Select at least one file",
            )
        )
    else:
        click.echo(f"No Shodan export found in {directory}.")
        selected = [OTHER]

    exports = [Path(p) for p in selected if p != OTHER]
    if OTHER in selected:
        while True:
            answer = _ask(
                ui.path(
                    "Path to a Shodan export (.json / .json.gz)",
                    validate=_validate_export,
                )
            )
            exports.append(_resolve(answer, directory))
            if not _ask(ui.confirm("Add another file?", default=False)):
                break
    return list(dict.fromkeys(exports))


def _choose_database(ui, directory: Path, allow_new: bool) -> Path:
    found = discover_databases(directory)
    choices = []
    if allow_new:
        choices.append(Choice("New database…", NEW))
    choices += [
        Choice(f"{_display(p, directory)}  ({describe_database(p)})", str(p))
        for p in found
    ]
    choices.append(Choice("Another database file…", OTHER))

    if len(choices) == 1 and not allow_new:
        answer = OTHER
    else:
        message = "Database to import into" if allow_new else "Database to report on"
        answer = _ask(ui.select(message, choices=choices))

    if answer == NEW:
        default = f"shodan_{date.today():%Y-%m-%d}"
        name = _ask(ui.text("New database name", default=default, validate=_not_empty))
        path = _resolve(db_path(name.strip()), directory)
        if path.exists():
            click.echo(
                f"{_display(path, directory)} already exists: new banners will be added to it."
            )
        return path
    if answer == OTHER:
        validate = None if allow_new else _validate_file
        answer = _ask(ui.path("Path to the database (.db)", validate=validate))
        return _resolve(db_path(answer), directory)
    return Path(answer)


def _choose_reports(ui, plan: Plan, directory: Path) -> None:
    formats = _ask(
        ui.checkbox(
            "Reports to generate",
            choices=[
                Choice("HTML report", "html", checked=True),
                Choice("osintracker JSON graph", "osint"),
            ],
            validate=lambda s: bool(s) or "Select at least one report",
        )
    )
    stem = plan.database.with_suffix("").name

    if "html" in formats:
        template = _ask(
            ui.select(
                "HTML template",
                choices=[
                    Choice("modern   self-contained, sorted by severity", "modern"),
                    Choice(
                        "classic  original Bulma layout (needs internet)", "classic"
                    ),
                    Choice("Custom template file…", OTHER),
                ],
                default="modern",
            )
        )
        if template == OTHER:
            answer = _ask(
                ui.path("Path to the Jinja2 template", validate=_validate_file)
            )
            template = str(_resolve(answer, directory))
        plan.template = template
        answer = _ask(ui.path("HTML report file", default=f"{stem}_report.html"))
        plan.html = _resolve(answer, directory)

    if "osint" in formats:
        alias = _ask(
            ui.text("osintracker central entity (empty for none)", default=stem)
        )
        plan.alias = alias.strip() or None
        answer = _ask(
            ui.path("osintracker JSON file", default=f"{stem}_osintracker.json")
        )
        plan.osint = _resolve(answer, directory)


def _summary(plan: Plan, directory: Path) -> None:
    click.echo()
    click.secho("Summary", bold=True)
    for export in plan.exports:
        click.echo(f"  import    {_display(export, directory)}")
    click.echo(f"  database  {_display(plan.database, directory)}")
    if plan.html:
        click.echo(
            f"  HTML      {_display(plan.html, directory)}  (template: {plan.template})"
        )
    if plan.osint:
        alias = f"  (entity: {plan.alias})" if plan.alias else ""
        click.echo(f"  osint     {_display(plan.osint, directory)}{alias}")
    click.echo()


def _execute(ui, plan: Plan, directory: Path) -> None:
    for export in plan.exports:
        click.echo(f"Importing {_display(export, directory)}…")
        stats = parse_file(export, plan.database)
        skipped = (
            f", {stats['skipped_lines']} invalid lines skipped"
            if stats["skipped_lines"]
            else ""
        )
        click.echo(
            f"  {stats['services']} new services, {stats['vulnerabilities']} new CVE entries{skipped}"
        )

    html = None
    if plan.html:
        html = export_html(plan.database, plan.html, plan.template)
        click.echo(f"HTML report written to {_display(Path(html), directory)}")
    if plan.osint:
        written = export_osintracker(plan.database, plan.osint, alias=plan.alias)
        click.echo(f"osintracker graph written to {_display(Path(written), directory)}")

    if html and _ask(ui.confirm("Open the HTML report now?", default=True)):
        click.launch(html)


def run(directory: Path | None = None, ui=questionary) -> Plan | None:
    """
    Runs the interactive session and returns the executed plan, or None when
    cancelled. `ui` is the prompt library (replaced by a fake in tests).
    """
    directory = Path(directory or Path.cwd()).resolve()
    try:
        action = _ask(
            ui.select(
                "What do you want to do?",
                choices=[
                    Choice("Import Shodan exports, then generate reports", "both"),
                    Choice("Import Shodan exports into a database", "import"),
                    Choice("Generate reports from an existing database", "report"),
                ],
            )
        )
        plan = Plan()
        if action in ("both", "import"):
            plan.exports = _choose_exports(ui, directory)
        plan.database = _choose_database(ui, directory, allow_new=action != "report")
        if action in ("both", "report"):
            _choose_reports(ui, plan, directory)

        _summary(plan, directory)
        if not _ask(ui.confirm("Run?", default=True)):
            click.echo("Nothing done.")
            return None
        _execute(ui, plan, directory)
        return plan
    except Aborted:
        click.echo("Cancelled.")
        return None

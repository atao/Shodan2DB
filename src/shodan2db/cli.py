"""Command-line interface: `shodan2db parse` and `shodan2db export`."""

from pathlib import Path

import click

from . import __version__
from .database import Shodan2DBError, parse_file
from .osintracker import export_osintracker
from .report import DEFAULT_TEMPLATE, export_html

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def _run(func, *args, **kwargs):
    """Turns library errors into clean CLI errors (message + exit code 1)."""
    try:
        return func(*args, **kwargs)
    except Shodan2DBError as e:
        raise click.ClickException(str(e)) from e


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, "-V", "--version")
def cli():
    """Parse Shodan JSON exports into SQLite and generate HTML / osintracker reports."""


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--input-file",
    "-i",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="JSON or JSON.GZ export file from Shodan.",
)
@click.option(
    "--database",
    "-d",
    required=True,
    type=click.Path(dir_okay=False),
    help="Target database name or path (.db is added if missing).",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode.")
def parse(input_file, database, verbose):
    """Parse a Shodan export and store it into a SQLite database."""
    _run(parse_file, input_file, database, verbose=verbose)


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--database",
    "-d",
    required=True,
    type=click.Path(dir_okay=False),
    help="Path to the SQLite database file.",
)
@click.option(
    "--format",
    "-f",
    "formats",
    type=click.Choice(["html", "osint", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Which export(s) to generate.",
)
@click.option(
    "--output",
    "-o",
    default="shodan.html",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Output path for the HTML report.",
)
@click.option(
    "--template-file",
    "-t",
    default=DEFAULT_TEMPLATE,
    show_default="built-in report.html",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Jinja2 template for the HTML report.",
)
@click.option(
    "--osint",
    default="shodan",
    show_default=True,
    help="Central entity name for the osintracker export.",
)
@click.option(
    "--osint-output",
    default="assets_osintracker.json",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Output path for the osintracker JSON file.",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode.")
def export(database, formats, output, template_file, osint, osint_output, verbose):
    """
    Export the database as an HTML report, an osintracker JSON file, or both.

    \b
    Examples:
      shodan2db export -d audit.db                       # both exports
      shodan2db export -d audit.db -f html -o report.html
      shodan2db export -d audit.db -f osint --osint "Campaign"
    """
    formats = formats.lower()
    if formats in ("html", "all"):
        _run(export_html, database, output, template_file, verbose=verbose)
    if formats in ("osint", "all"):
        _run(export_osintracker, database, osint_output, alias=osint, verbose=verbose)


def main():
    cli()

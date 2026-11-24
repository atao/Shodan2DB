"""Command-line interface: `shodan2db parse`, `export` and `interactive`."""

import sys

import click

from . import __version__
from .database import Shodan2DBError, parse_file
from .osintracker import export_osintracker
from .report import BUILTIN_TEMPLATES, export_html

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def _run(func, *args, **kwargs):
    """Turns library errors into clean CLI errors (message + exit code 1)."""
    try:
        return func(*args, **kwargs)
    except Shodan2DBError as e:
        raise click.ClickException(str(e)) from e


def _is_terminal():
    return sys.stdin.isatty() and sys.stdout.isatty()


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.version_option(__version__, "-V", "--version")
@click.pass_context
def cli(ctx):
    """
    Parse Shodan JSON exports into SQLite and generate HTML / osintracker reports.

    Run without a command in a terminal to start the interactive mode.
    """
    if ctx.invoked_subcommand is None:
        if _is_terminal():
            ctx.invoke(interactive)
        else:
            click.echo(ctx.get_help())


@cli.command(context_settings=CONTEXT_SETTINGS)
def interactive():
    """Choose exports, database and reports from menus."""
    if not _is_terminal():
        raise click.ClickException("Interactive mode needs a terminal.")
    # Imported here so the regular commands do not load prompt_toolkit
    from .interactive import run

    _run(run)


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
    "--template",
    "--template-file",
    "-t",
    "template",
    default="classic",
    show_default=True,
    help=f"Built-in template ({', '.join(BUILTIN_TEMPLATES)}) or path to a Jinja2 template.",
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
def export(database, formats, output, template, osint, osint_output, verbose):
    """
    Export the database as an HTML report, an osintracker JSON file, or both.

    \b
    Examples:
      shodan2db export -d audit.db                       # both exports
      shodan2db export -d audit.db -f html -o report.html
      shodan2db export -d audit.db -f html -t modern
      shodan2db export -d audit.db -f osint --osint "Campaign"
    """
    formats = formats.lower()
    if formats in ("html", "all"):
        _run(export_html, database, output, template, verbose=verbose)
    if formats in ("osint", "all"):
        _run(export_osintracker, database, osint_output, alias=osint, verbose=verbose)


def main():
    cli()

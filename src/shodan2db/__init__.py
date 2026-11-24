"""Parse Shodan JSON exports into SQLite and generate HTML / osintracker reports."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("shodan2db")
except PackageNotFoundError:  # running from a source tree without install
    __version__ = "unknown"

from .database import Shodan2DBError, init_database, open_database, parse_file
from .osintracker import OsintrackerExporter, export_osintracker
from .report import DEFAULT_TEMPLATE, export_html

__all__ = [
    "DEFAULT_TEMPLATE",
    "OsintrackerExporter",
    "Shodan2DBError",
    "__version__",
    "export_html",
    "export_osintracker",
    "init_database",
    "open_database",
    "parse_file",
]

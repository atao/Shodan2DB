import pytest
from click.testing import CliRunner

from conftest import banner, write_export
from shodan2db.cli import cli


def invoke(*args):
    return CliRunner().invoke(cli, [str(a) for a in args])


@pytest.mark.parametrize(
    "fmt, html, osint",
    [("html", True, False), ("osint", False, True), ("all", True, True)],
)
def test_export_format(tmp_path, populated_db, fmt, html, osint):
    html_path, json_path = tmp_path / "r.html", tmp_path / "o.json"
    result = invoke(
        "export", "-d", populated_db, "-f", fmt,
        "-o", html_path, "--osint-output", json_path,
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert html_path.exists() is html
    assert json_path.exists() is osint


def test_default_template_works_from_any_directory(tmp_path, populated_db, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = invoke("export", "-d", populated_db, "-f", "html")

    assert result.exit_code == 0, result.output
    assert (tmp_path / "shodan.html").exists()


def test_parse_then_export(tmp_path):
    export = write_export(tmp_path / "in.json", [banner(80)])
    db = tmp_path / "audit"

    assert invoke("parse", "-i", export, "-d", db).exit_code == 0
    assert (tmp_path / "audit.db").exists()
    result = invoke("export", "-d", db, "-f", "html", "-o", tmp_path / "r.html")
    assert result.exit_code == 0, result.output


def test_missing_database_is_a_clean_error(tmp_path):
    result = invoke("export", "-d", tmp_path / "missing.db")

    assert result.exit_code == 1
    assert "Error: Database not found" in result.output
    assert "Traceback" not in result.output


def test_version():
    result = invoke("--version")
    assert result.exit_code == 0
    assert "version" in result.output


def test_builtin_template_by_name(tmp_path, populated_db):
    result = invoke(
        "export",
        "-d",
        populated_db,
        "-f",
        "html",
        "-t",
        "modern",
        "-o",
        tmp_path / "m.html",
    )

    assert result.exit_code == 0, result.output
    assert "Findings by severity" in (tmp_path / "m.html").read_text()

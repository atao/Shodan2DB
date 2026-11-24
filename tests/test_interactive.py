import gzip
import json
import sqlite3
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from conftest import VULN, banner, write_export
from shodan2db import interactive, parse_file
from shodan2db.cli import cli
from shodan2db.interactive import NEW, OTHER


class FakeUI:
    """Replays scripted answers; None simulates Ctrl-C."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []

    def _question(self, kind, message, **kwargs):
        self.asked.append((kind, message, kwargs))
        assert self.answers, f"unexpected prompt: {message}"
        answer = self.answers.pop(0)
        if callable(answer):
            answer = answer(kwargs)
        return SimpleNamespace(ask=lambda: answer)

    def __getattr__(self, kind):
        if kind in ("select", "checkbox", "path", "text", "confirm"):
            return lambda message, **kwargs: self._question(kind, message, **kwargs)
        raise AttributeError(kind)


def choice_values(kwargs):
    return [c.value for c in kwargs["choices"] if hasattr(c, "value")]


@pytest.fixture(autouse=True)
def no_browser(monkeypatch):
    monkeypatch.setattr(
        interactive.click, "launch", lambda *a, **k: pytest.fail("launched")
    )


@pytest.fixture
def workdir(tmp_path):
    write_export(tmp_path / "scan.json", [banner(80, {"CVE-2024-0001": VULN})])
    (tmp_path / "package.json").write_text('{"name": "not shodan"}\n')
    return tmp_path


def test_discover_exports(workdir):
    with gzip.open(workdir / "older.json.gz", "wt") as f:
        f.write(json.dumps(banner(22)) + "\n")
    (workdir / ".venv").mkdir()
    write_export(workdir / ".venv" / "hidden.json", [banner(1)])

    names = sorted(p.name for p in interactive.discover_exports(workdir))
    assert names == ["older.json.gz", "scan.json"]


def test_discover_and_describe_databases(workdir, populated_db, tmp_path):
    (tmp_path / "fake.db").write_text("not sqlite")

    found = interactive.discover_databases(tmp_path)
    assert [p.name for p in found] == ["test.db"]
    assert interactive.describe_database(found[0]) == "2 hosts, 2 CVEs"


def test_describe_database_is_read_only(tmp_path):
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    assert interactive.describe_database(empty) == "not a Shodan2DB database"
    assert (
        interactive.describe_database(tmp_path / "missing.db")
        == "not a Shodan2DB database"
    )
    assert not (tmp_path / "missing.db").exists()


def test_import_then_report(workdir):
    scan = str(workdir / "scan.json")
    ui = FakeUI(
        "both",
        lambda kw: [v for v in choice_values(kw) if v == scan],  # pre-checked export
        NEW,
        "audit",
        ["html", "osint"],
        "modern",
        "audit.html",
        "Audit",
        "graph.json",
        True,  # run
        False,  # do not open the report
    )
    plan = interactive.run(workdir, ui=ui)

    assert plan.database == workdir / "audit.db"
    assert "Findings by severity" in (workdir / "audit.html").read_text()
    graph = json.loads((workdir / "graph.json").read_text())
    assert any(e["value"] == "Audit" for e in graph["entities"])
    # The new export was the first, pre-checked choice
    checkbox = next(kw for kind, _, kw in ui.asked if kind == "checkbox")
    assert checkbox["choices"][0].checked


def test_report_only_lists_existing_databases(workdir, populated_db, monkeypatch):
    ui = FakeUI(
        "report",
        lambda kw: next(v for v in choice_values(kw) if v.endswith("test.db")),
        ["html"],
        "classic",
        "r.html",
        True,
        True,  # open the report
    )
    launched = []
    monkeypatch.setattr(interactive.click, "launch", launched.append)
    interactive.run(workdir, ui=ui)

    db_prompt = ui.asked[1][2]
    assert NEW not in choice_values(db_prompt)
    assert launched == [str(workdir / "r.html")]


def test_other_export_path(workdir, tmp_path_factory):
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    other = write_export(elsewhere / "other.json", [banner(443)])
    ui = FakeUI("import", [OTHER], other, False, NEW, "db", True)
    plan = interactive.run(workdir, ui=ui)

    assert [str(p) for p in plan.exports] == [other]
    assert (workdir / "db.db").exists()


def test_cancel_does_nothing(workdir, capsys):
    ui = FakeUI("both", None)
    assert interactive.run(workdir, ui=ui) is None
    assert "Cancelled." in capsys.readouterr().out
    assert not list(workdir.glob("*.db"))


def test_declining_the_summary_does_nothing(workdir):
    scan = str(workdir / "scan.json")
    ui = FakeUI("import", [scan], NEW, "db", False)
    assert interactive.run(workdir, ui=ui) is None
    assert not (workdir / "db.db").exists()


def test_validators(workdir):
    assert interactive._validate_export(str(workdir / "scan.json")) is True
    assert interactive._validate_export(str(workdir / "nope.json")) == "File not found"
    (workdir / "x.txt").write_text("")
    assert "json" in interactive._validate_export(str(workdir / "x.txt"))
    assert interactive._not_empty("  ") == "Required"


def test_reimport_through_interactive_mode_adds_nothing(workdir):
    parse_file(workdir / "scan.json", workdir / "db.db")
    ui = FakeUI("import", [str(workdir / "scan.json")], str(workdir / "db.db"), True)
    interactive.run(workdir, ui=ui)
    # still one banner: the import is idempotent
    conn = sqlite3.connect(workdir / "db.db")
    assert conn.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 1
    conn.close()


def test_cli_without_terminal_shows_help():
    result = CliRunner().invoke(cli, [])
    assert result.exit_code == 0
    assert "interactive" in result.output


def test_interactive_command_requires_terminal():
    result = CliRunner().invoke(cli, ["interactive"])
    assert result.exit_code == 1
    assert "needs a terminal" in result.output

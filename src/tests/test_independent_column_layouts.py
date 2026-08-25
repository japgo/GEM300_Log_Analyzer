from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import COLUMNS, Gem300DesktopApp


class _Variable:
    def __init__(self, value: bool) -> None:
        self.value = value

    def get(self) -> bool:
        return self.value

    def set(self, value: bool) -> None:
        self.value = value


class _Tree:
    def __init__(self) -> None:
        self.displaycolumns: list[str] = []

    def configure(self, **kwargs) -> None:
        if "displaycolumns" in kwargs:
            self.displaycolumns = list(kwargs["displaycolumns"])


def _layout_app() -> Gem300DesktopApp:
    app = object.__new__(Gem300DesktopApp)
    app.visible_columns = ["time", "message"]
    app.all_logs_visible_columns = ["file", "line", "message"]
    app.column_visible_vars = {
        column: _Variable(column in app.visible_columns) for column in COLUMNS
    }
    app.all_logs_column_visible_vars = {
        column: _Variable(column in app.all_logs_visible_columns) for column in COLUMNS
    }
    app.tree = _Tree()
    app.all_logs_tree = _Tree()
    return app


def test_scoped_settings_load_independent_column_layouts() -> None:
    app = object.__new__(Gem300DesktopApp)
    app.settings = {
        "filtered_column_order": ["message", "time"],
        "filtered_visible_columns": ["message"],
        "all_logs_column_order": ["file", "line", "message"],
        "all_logs_visible_columns": ["file", "line"],
    }

    assert app._load_visible_columns("filtered") == ["message"]
    assert app._load_visible_columns("all_logs") == ["file", "line"]


def test_legacy_settings_are_migrated_to_both_column_layouts() -> None:
    app = object.__new__(Gem300DesktopApp)
    app.settings = {
        "column_order": ["time", "message"],
        "visible_columns": ["time", "message"],
    }

    expected = ["bookmark", "memo", "time", "message"]
    assert app._load_visible_columns("filtered") == expected
    assert app._load_visible_columns("all_logs") == expected


def test_moving_filtered_column_does_not_change_all_logs_layout() -> None:
    app = _layout_app()

    changed = app._move_visible_column("filtered", "message", "time")

    assert changed is True
    assert app.visible_columns == ["message", "time"]
    assert app.all_logs_visible_columns == ["file", "line", "message"]
    assert app.tree.displaycolumns == ["message", "time"]
    assert app.all_logs_tree.displaycolumns == []


def test_moving_all_logs_column_does_not_change_filtered_layout() -> None:
    app = _layout_app()

    changed = app._move_visible_column("all_logs", "message", "file")

    assert changed is True
    assert app.visible_columns == ["time", "message"]
    assert app.all_logs_visible_columns == ["message", "file", "line"]
    assert app.tree.displaycolumns == []
    assert app.all_logs_tree.displaycolumns == ["message", "file", "line"]


def test_session_layout_restores_each_table_independently() -> None:
    view = {
        "filtered_column_order": ["message", "time"],
        "filtered_visible_columns": ["message", "time"],
        "all_logs_column_order": ["line", "file", "message"],
        "all_logs_visible_columns": ["line", "file"],
    }

    assert Gem300DesktopApp._session_column_layout(view, "filtered") == [
        "message",
        "time",
    ]
    assert Gem300DesktopApp._session_column_layout(view, "all_logs") == [
        "line",
        "file",
    ]

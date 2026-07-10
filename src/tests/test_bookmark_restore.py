from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _Var:
    def __init__(self, value: int) -> None:
        self.value = value

    def get(self) -> int:
        return self.value


class _TextVar:
    def __init__(self) -> None:
        self.value = ""

    def set(self, value: str) -> None:
        self.value = value


class _Tree:
    def __init__(self) -> None:
        self.items: list[str] = []
        self.selected: str | None = None
        self.focused: str | None = None
        self.seen: str | None = None

    def get_children(self) -> tuple[str, ...]:
        return tuple(self.items)

    def delete(self, *items: str) -> None:
        for item in items:
            if item in self.items:
                self.items.remove(item)

    def insert(self, _parent: str, _where: str, iid: str, **_kwargs) -> None:
        self.items.append(iid)

    def exists(self, item: str) -> bool:
        return item in self.items

    def selection_set(self, item: str) -> None:
        self.selected = item

    def focus(self, item: str) -> None:
        self.focused = item

    def see(self, item: str) -> None:
        self.seen = item


class _AppShim:
    _filtered_index_for_entry_key = Gem300DesktopApp._filtered_index_for_entry_key
    _select_filtered_entry_by_key = Gem300DesktopApp._select_filtered_entry_by_key
    refresh_table = Gem300DesktopApp.refresh_table

    def __init__(self, entries: list[LogEntry]) -> None:
        self.filtered_entries = entries
        self.tree = _Tree()
        self.display_rows_var = _Var(2)
        self.matched_keywords_by_entry = {}
        self.summary_var = _TextVar()
        self.detail_shown = False
        self.detail_cleared = False

    @staticmethod
    def _entry_key(entry: LogEntry) -> str:
        return f"{entry.source_file}|{entry.line_no}|{entry.display_time}"

    @staticmethod
    def _is_bookmarked(_entry: LogEntry) -> bool:
        return False

    @staticmethod
    def _entry_memo(_entry: LogEntry) -> str:
        return ""

    @staticmethod
    def _time_delta_for_index(_index: int) -> str:
        return ""

    def _refresh_bookmark_timeline(self) -> None:
        pass

    def _refresh_stats_panel(self) -> None:
        pass

    def show_selected_detail(self) -> None:
        self.detail_shown = True

    def _clear_detail(self) -> None:
        self.detail_cleared = True


def _entry(line_no: int) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 10, 12, 0, line_no),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=f"log {line_no}",
        line_no=line_no,
    )


def test_refresh_table_expands_display_limit_and_selects_focus_entry() -> None:
    entries = [_entry(index) for index in range(1, 6)]
    app = _AppShim(entries)
    focus_key = app._entry_key(entries[3])

    Gem300DesktopApp.refresh_table(app, focus_entry_key=focus_key)

    assert app.tree.items == ["0", "1", "2", "3"]
    assert app.tree.selected == "3"
    assert app.tree.focused == "3"
    assert app.tree.seen == "3"
    assert app.detail_shown is True
    assert app.detail_cleared is False


if __name__ == "__main__":
    test_refresh_table_expands_display_limit_and_selects_focus_entry()
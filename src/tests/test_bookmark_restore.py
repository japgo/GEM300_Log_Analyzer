from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _BoolVar:
    def __init__(self, value: bool) -> None:
        self.value = value

    def get(self) -> bool:
        return self.value

    def set(self, value: bool) -> None:
        self.value = value


class _StringVar:
    def __init__(self, value: str = "") -> None:
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


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
        self.selected: tuple[str, ...] = ()
        self.focused: str | None = None
        self.focus_set_called = False
        self.seen: str | None = None
        self.row_by_y: dict[int, str] = {}

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

    def selection(self) -> tuple[str, ...]:
        return self.selected

    def selection_set(self, *items: str) -> None:
        self.selected = tuple(items)

    def selection_add(self, *items: str | tuple[str, ...]) -> None:
        selected = set(self.selected)
        for item in items:
            if isinstance(item, tuple):
                selected.update(item)
            else:
                selected.add(item)
        self.selected = tuple(sorted(selected, key=int))

    def selection_remove(self, *items: str | tuple[str, ...]) -> None:
        selected = set(self.selected)
        for item in items:
            if isinstance(item, tuple):
                selected.difference_update(item)
            else:
                selected.discard(item)
        self.selected = tuple(sorted(selected, key=int))

    def focus(self, item: str) -> None:
        self.focused = item

    def focus_set(self) -> None:
        self.focus_set_called = True

    def see(self, item: str) -> None:
        self.seen = item

    @staticmethod
    def identify_region(_x: int, _y: int) -> str:
        return "cell"

    def identify_row(self, y: int) -> str:
        return self.row_by_y.get(y, "")



class _Root:
    def __init__(self) -> None:
        self.idle_callbacks = []

    def after_idle(self, callback) -> None:
        self.idle_callbacks.append(callback)

    def run_idle(self) -> None:
        callbacks = list(self.idle_callbacks)
        self.idle_callbacks.clear()
        for callback in callbacks:
            callback()

class _AppShim:
    _filtered_index_for_entry_key = Gem300DesktopApp._filtered_index_for_entry_key
    _entry_index_for_key = Gem300DesktopApp._entry_index_for_key
    _select_filtered_entry_by_key = Gem300DesktopApp._select_filtered_entry_by_key
    _selected_display_indices = Gem300DesktopApp._selected_display_indices
    _first_selected_display_index = Gem300DesktopApp._first_selected_display_index
    _selected_single_entry_key = Gem300DesktopApp._selected_single_entry_key
    _set_tree_selection = Gem300DesktopApp._set_tree_selection
    _restore_tree_selection_after_control_click = Gem300DesktopApp._restore_tree_selection_after_control_click
    _on_tree_control_click = Gem300DesktopApp._on_tree_control_click
    _is_control_click = staticmethod(Gem300DesktopApp._is_control_click)
    clear_result_search = Gem300DesktopApp.clear_result_search
    find_result_match = Gem300DesktopApp.find_result_match
    _navigate_result_match = Gem300DesktopApp._navigate_result_match
    _result_match_indices = Gem300DesktopApp._result_match_indices
    _find_navigation_index = staticmethod(Gem300DesktopApp._find_navigation_index)
    _disable_bookmark_only_for_analysis = Gem300DesktopApp._disable_bookmark_only_for_analysis
    _focus_result_table = Gem300DesktopApp._focus_result_table
    select_all_filtered_logs = Gem300DesktopApp.select_all_filtered_logs
    toggle_selected_bookmarks = Gem300DesktopApp.toggle_selected_bookmarks
    refresh_table = Gem300DesktopApp.refresh_table
    refresh_all_logs_table = Gem300DesktopApp.refresh_all_logs_table
    on_filtered_result_selected_in_search_mode = (
        Gem300DesktopApp.on_filtered_result_selected_in_search_mode
    )
    _format_time_delta = staticmethod(Gem300DesktopApp._format_time_delta)

    def __init__(self, entries: list[LogEntry]) -> None:
        self.entries = entries
        self.filtered_entries = entries
        self.tree = _Tree()
        self.all_logs_tree = _Tree()
        self.root = _Root()
        self.display_rows_var = _Var(2)
        self.bookmark_only_var = _BoolVar(True)
        self.always_include_bookmarks_var = _BoolVar(False)
        self.case_sensitive_var = _BoolVar(False)
        self.regex_search_var = _BoolVar(False)
        self.result_search_var = _StringVar("needle")
        self._pending_filter_restore_key: str | None = None
        self.apply_filters_called = False
        self.settings_saved = False
        self.matched_keywords_by_entry = {}
        self.bookmarks: dict[str, str] = {}
        self.summary_var = _TextVar()
        self.all_logs_title_var = _TextVar()
        self.status_var = _TextVar()
        self.search_view_mode_active = False
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

    def _save_settings(self) -> None:
        self.settings_saved = True

    def apply_filters(self) -> None:
        self.apply_filters_called = True

    def _refresh_bookmark_timeline(self) -> None:
        pass

    def _refresh_stats_panel(self) -> None:
        pass

    def show_selected_detail(self) -> None:
        self.detail_shown = True

    def _clear_detail(self) -> None:
        self.detail_cleared = True


class _Event:
    def __init__(self, y: int, state: int = 0) -> None:
        self.x = 10
        self.y = y
        self.state = state


def _entry(line_no: int, message: str | None = None) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 10, 12, 0, line_no),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=message or f"log {line_no}",
        line_no=line_no,
    )


def test_refresh_table_expands_display_limit_and_selects_focus_entry() -> None:
    entries = [_entry(index) for index in range(1, 6)]
    app = _AppShim(entries)
    focus_key = app._entry_key(entries[3])

    Gem300DesktopApp.refresh_table(app, focus_entry_key=focus_key)

    assert app.tree.items == ["0", "1", "2", "3"]
    assert app.tree.selected == ("3",)
    assert app.tree.focused == "3"
    assert app.tree.seen == "3"
    assert app.detail_shown is True
    assert app.detail_cleared is False


def test_ctrl_a_expands_hidden_results_and_selects_all_filtered_logs() -> None:
    entries = [_entry(index) for index in range(1, 6)]
    app = _AppShim(entries)

    app.refresh_table()
    assert app.tree.items == ["0", "1"]

    result = app.select_all_filtered_logs()

    assert result == "break"
    assert app.tree.items == ["0", "1", "2", "3", "4"]
    assert app.tree.selected == ("0", "1", "2", "3", "4")
    assert app.tree.focused == "0"
    assert app.tree.seen == "0"
    assert app.tree.focus_set_called is True
    assert app.display_rows_var.get() == 2
    assert app.status_var.value == "현재 검색 결과 5건을 모두 선택했습니다."


def test_bookmark_only_control_click_toggles_selection_without_order_reset() -> None:
    entries = [_entry(index) for index in range(1, 5)]
    app = _AppShim(entries)
    app.tree.items = ["0", "1", "2", "3"]
    app.tree.row_by_y = {30: "2", 10: "0", 20: "1"}

    assert Gem300DesktopApp._on_tree_control_click(app, _Event(30)) == "break"
    assert app.tree.selection() == ("2",)
    assert Gem300DesktopApp._on_tree_control_click(app, _Event(10)) == "break"
    assert app.tree.selection() == ("0", "2")
    assert Gem300DesktopApp._on_tree_control_click(app, _Event(20)) == "break"
    assert app.tree.selection() == ("0", "1", "2")


def test_bookmark_only_button_press_ctrl_click_above_first_selection_keeps_previous() -> None:
    entries = [_entry(index) for index in range(1, 6)]
    app = _AppShim(entries)
    app.tree.items = ["0", "1", "2", "3", "4"]
    app.tree.row_by_y = {40: "3", 10: "0"}
    app.tree.selection_set("3")

    assert Gem300DesktopApp._on_tree_button_press(app, _Event(10, state=0x0004)) == "break"

    assert app.tree.selection() == ("0", "3")
    assert app.tree.focused == "0"
    assert app.tree.seen == "0"


def test_clear_result_search_keeps_current_results_and_selection() -> None:
    entries = [_entry(index) for index in range(1, 5)]
    app = _AppShim(entries)
    app.tree.items = ["0", "1", "2", "3"]
    app.tree.selection_set("2")

    Gem300DesktopApp.clear_result_search(app)

    assert app.result_search_var.get() == ""
    assert app.tree.selection() == ("2",)
    assert app.apply_filters_called is False
    assert app.status_var.value == "결과 내 찾기 검색어를 지웠습니다."


def test_find_result_shortcuts_navigate_and_wrap() -> None:
    entries = [
        _entry(1, "needle first"),
        _entry(2, "other"),
        _entry(3, "needle second"),
        _entry(4, "other"),
        _entry(5, "needle third"),
    ]
    app = _AppShim(entries)
    app.refresh_table()

    assert app.find_result_match(1) == "break"
    assert app.tree.selected == ("0",)
    assert app.find_result_match(1) == "break"
    assert app.tree.selected == ("2",)
    assert app.find_result_match(-1) == "break"
    assert app.tree.selected == ("0",)
    assert app.find_result_match(-1) == "break"
    assert app.tree.selected == ("4",)
    assert app.tree.seen == "4"
    assert app.tree.items == ["0", "1", "2", "3", "4"]
    assert app.status_var.value == "이전 찾기: 일치 3/3, 결과 행 5/5 (needle)"


def test_find_result_does_not_apply_filters_or_reduce_results() -> None:
    entries = [_entry(1, "needle"), _entry(2, "other")]
    app = _AppShim(entries)
    app.refresh_table()

    assert app.find_result_match(1) == "break"
    assert app.apply_filters_called is False
    assert app.filtered_entries == entries
    assert app.tree.items == ["0", "1"]


def test_find_result_in_search_view_also_moves_full_log_selection() -> None:
    entries = [_entry(1, "other"), _entry(2, "needle"), _entry(3, "other")]
    app = _AppShim(entries)
    app.search_view_mode_active = True
    app.refresh_table()

    app.find_result_match(1)

    assert app.tree.selected == ("1",)
    assert app.all_logs_tree.selected == ("1",)
    assert app.all_logs_tree.seen == "1"


def test_search_view_result_selection_moves_to_matching_full_log() -> None:
    entries = [_entry(index) for index in range(1, 6)]
    app = _AppShim(entries)
    app.filtered_entries = [entries[3]]
    app.search_view_mode_active = True
    app.refresh_table()
    app.tree.selection_set("0")

    app.on_filtered_result_selected_in_search_mode()

    assert app.all_logs_tree.items == ["0", "1", "2", "3"]
    assert app.all_logs_tree.selected == ("3",)
    assert app.all_logs_tree.focused == "3"
    assert app.all_logs_tree.seen == "3"
    assert app.status_var.value.startswith("전체 로그 이동: #4")


def test_analysis_start_disables_bookmark_only_filter() -> None:
    app = _AppShim([_entry(1)])
    app._pending_filter_restore_key = app._entry_key(app.filtered_entries[0])

    Gem300DesktopApp._disable_bookmark_only_for_analysis(app)

    assert app.bookmark_only_var.get() is False
    assert app._pending_filter_restore_key is None
    assert app.settings_saved is True

def test_bookmark_only_ctrl_click_idle_restore_survives_tk_anchor_reset() -> None:
    entries = [_entry(index) for index in range(1, 6)]
    app = _AppShim(entries)
    app.tree.items = ["0", "1", "2", "3", "4"]
    app.tree.row_by_y = {40: "3", 10: "0"}
    app.tree.selection_set("3")

    assert Gem300DesktopApp._on_tree_control_click(app, _Event(10, state=0x0004)) == "break"
    app.tree.selection_set("0")
    app.root.run_idle()

    assert app.tree.selection() == ("0", "3")
    assert app.tree.focused == "0"
    assert app.tree.seen == "0"

def test_toggle_bookmark_keeps_keyboard_focus_on_result_table() -> None:
    entries = [_entry(index) for index in range(1, 4)]
    app = _AppShim(entries)
    app.bookmark_only_var.set(False)
    app.tree.items = ["0", "1", "2"]
    app.tree.selection_set("1")

    Gem300DesktopApp.toggle_selected_bookmarks(app)

    assert app.tree.focus_set_called is True
    assert app.tree.selection() == ("1",)
    assert app._entry_key(entries[1]) in app.bookmarks


def test_toggle_bookmark_in_bookmark_only_restores_focus_after_filter() -> None:
    entries = [_entry(index) for index in range(1, 4)]
    app = _AppShim(entries)
    app.bookmark_only_var.set(True)
    app.tree.items = ["0", "1", "2"]
    app.tree.selection_set("1")

    Gem300DesktopApp.toggle_selected_bookmarks(app)
    assert app.apply_filters_called is True
    assert app.tree.focus_set_called is False

    app.root.run_idle()
    assert app.tree.focus_set_called is True

if __name__ == "__main__":
    test_refresh_table_expands_display_limit_and_selects_focus_entry()
    test_bookmark_only_control_click_toggles_selection_without_order_reset()
    test_bookmark_only_button_press_ctrl_click_above_first_selection_keeps_previous()
    test_bookmark_only_ctrl_click_idle_restore_survives_tk_anchor_reset()
    test_clear_result_search_keeps_current_results_and_selection()
    test_find_result_shortcuts_navigate_and_wrap()
    test_find_result_does_not_apply_filters_or_reduce_results()
    test_find_result_in_search_view_also_moves_full_log_selection()
    test_analysis_start_disables_bookmark_only_filter()
    test_toggle_bookmark_keeps_keyboard_focus_on_result_table()
    test_toggle_bookmark_in_bookmark_only_restores_focus_after_filter()

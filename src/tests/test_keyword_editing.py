from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp


class _StringVar:
    def __init__(self, value: str = "") -> None:
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


class _KeywordEditingShim:
    add_keyword = Gem300DesktopApp.add_keyword
    remove_selected_keyword = Gem300DesktopApp.remove_selected_keyword
    clear_keywords = Gem300DesktopApp.clear_keywords
    add_exclude_keyword = Gem300DesktopApp.add_exclude_keyword
    remove_selected_exclude_keyword = Gem300DesktopApp.remove_selected_exclude_keyword
    clear_exclude_keywords = Gem300DesktopApp.clear_exclude_keywords
    _mark_keyword_filters_pending = Gem300DesktopApp._mark_keyword_filters_pending

    def __init__(self) -> None:
        self.keywords: list[tuple[str, str]] = []
        self.exclude_keywords: list[str] = []
        self.keyword_var = _StringVar()
        self.keyword_mode_var = _StringVar("AND")
        self.exclude_keyword_var = _StringVar()
        self.status_var = _StringVar()
        self.selected_keyword_index: int | None = None
        self.selected_exclude_keyword_index: int | None = None
        self.apply_filters_count = 0

    def _render_keyword_tags(self) -> None:
        pass

    def _render_exclude_keyword_tags(self) -> None:
        pass

    def apply_filters(self) -> None:
        self.apply_filters_count += 1


def test_include_keyword_edits_wait_for_explicit_filter_apply() -> None:
    app = _KeywordEditingShim()

    app.keyword_var.set("CarrierObject")
    app.add_keyword()
    app.selected_keyword_index = 0
    app.keyword_mode_var.set("OR")
    app.keyword_var.set("SubstrateObject")
    app.add_keyword()
    app.selected_keyword_index = 0
    assert app.remove_selected_keyword() == "break"

    app.keyword_var.set("LoadPortObject")
    app.add_keyword()
    app.clear_keywords()

    assert app.keywords == []
    assert app.apply_filters_count == 0
    assert app.status_var.get().endswith(
        "검색/필터 적용 버튼을 눌러 반영하세요."
    )
    app.apply_filters()
    assert app.apply_filters_count == 1


def test_exclude_keyword_edits_wait_for_explicit_filter_apply() -> None:
    app = _KeywordEditingShim()

    app.exclude_keyword_var.set("DEBUG")
    app.add_exclude_keyword()
    app.selected_exclude_keyword_index = 0
    app.exclude_keyword_var.set("TRACE")
    app.add_exclude_keyword()
    app.selected_exclude_keyword_index = 0
    assert app.remove_selected_exclude_keyword() == "break"

    app.exclude_keyword_var.set("HEARTBEAT")
    app.add_exclude_keyword()
    app.clear_exclude_keywords()

    assert app.exclude_keywords == []
    assert app.apply_filters_count == 0
    assert app.status_var.get().endswith(
        "검색/필터 적용 버튼을 눌러 반영하세요."
    )
    app.apply_filters()
    assert app.apply_filters_count == 1

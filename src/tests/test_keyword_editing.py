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


class _BoolVar:
    def __init__(self, value: bool = False) -> None:
        self.value = value

    def get(self) -> bool:
        return self.value

    def set(self, value: bool) -> None:
        self.value = value


class _KeywordEditingShim:
    add_keyword = Gem300DesktopApp.add_keyword
    remove_selected_keyword = Gem300DesktopApp.remove_selected_keyword
    clear_keywords = Gem300DesktopApp.clear_keywords
    add_exclude_keyword = Gem300DesktopApp.add_exclude_keyword
    remove_selected_exclude_keyword = Gem300DesktopApp.remove_selected_exclude_keyword
    clear_exclude_keywords = Gem300DesktopApp.clear_exclude_keywords
    clear_selected_keyword = Gem300DesktopApp.clear_selected_keyword
    clear_selected_exclude_keyword = Gem300DesktopApp.clear_selected_exclude_keyword
    on_search_option_changed = Gem300DesktopApp.on_search_option_changed
    apply_filters_shortcut = Gem300DesktopApp.apply_filters_shortcut
    load_search_preset = Gem300DesktopApp.load_search_preset
    _mark_keyword_filters_pending = Gem300DesktopApp._mark_keyword_filters_pending

    def __init__(self) -> None:
        self.keywords: list[tuple[str, str]] = []
        self.exclude_keywords: list[str] = []
        self.keyword_var = _StringVar()
        self.keyword_mode_var = _StringVar("AND")
        self.exclude_keyword_var = _StringVar()
        self.preset_name_var = _StringVar()
        self.status_var = _StringVar()
        self.case_sensitive_var = _BoolVar()
        self.regex_search_var = _BoolVar()
        self.always_include_bookmarks_var = _BoolVar()
        self.search_presets: dict[str, dict] = {}
        self.selected_keyword_index: int | None = None
        self.selected_exclude_keyword_index: int | None = None
        self.apply_filters_count = 0

    def _render_keyword_tags(self) -> None:
        pass

    def _render_exclude_keyword_tags(self) -> None:
        pass

    def _refresh_keyword_listboxes(self) -> None:
        self._render_keyword_tags()
        self._render_exclude_keyword_tags()

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
        "검색/필터 적용 버튼 또는 F5를 눌러 반영하세요."
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
        "검색/필터 적용 버튼 또는 F5를 눌러 반영하세요."
    )
    app.apply_filters()
    assert app.apply_filters_count == 1


def test_search_option_change_waits_for_button_or_f5() -> None:
    app = _KeywordEditingShim()

    app.case_sensitive_var.set(True)
    app.on_search_option_changed()

    assert app.apply_filters_count == 0
    assert app.status_var.get().startswith("검색 옵션 변경됨.")
    assert app.apply_filters_shortcut() == "break"
    assert app.apply_filters_count == 1


def test_loading_preset_waits_for_explicit_filter_apply() -> None:
    app = _KeywordEditingShim()
    app.search_presets["carrier"] = {
        "keywords": [{"mode": "OR", "keyword": "CarrierObject"}],
        "exclude_keywords": ["DEBUG"],
        "case_sensitive": True,
        "use_regex": True,
        "always_include_bookmarks": True,
    }

    app.load_search_preset("carrier")

    assert app.keywords == [("OR", "CarrierObject")]
    assert app.exclude_keywords == ["DEBUG"]
    assert app.case_sensitive_var.get() is True
    assert app.regex_search_var.get() is True
    assert app.always_include_bookmarks_var.get() is True
    assert app.apply_filters_count == 0
    assert app.status_var.get().startswith("검색 프리셋 불러옴: carrier.")


def test_escape_clears_keyword_item_selection_without_applying_filters() -> None:
    app = _KeywordEditingShim()
    app.keywords = [("AND", "CarrierObject")]
    app.exclude_keywords = ["DEBUG"]
    app.selected_keyword_index = 0
    app.selected_exclude_keyword_index = 0
    app.keyword_var.set("CarrierObject")
    app.exclude_keyword_var.set("DEBUG")

    assert app.clear_selected_keyword() == "break"
    assert app.selected_keyword_index is None
    assert app.keyword_var.get() == ""
    assert app.clear_selected_exclude_keyword() == "break"
    assert app.selected_exclude_keyword_index is None
    assert app.exclude_keyword_var.get() == ""
    assert app.apply_filters_count == 0

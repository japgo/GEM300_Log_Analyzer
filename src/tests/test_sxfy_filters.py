from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import desktop_app
from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _BoolVar:
    def __init__(self, value: bool = False) -> None:
        self.value = value

    def get(self) -> bool:
        return self.value

    def set(self, value: bool) -> None:
        self.value = value


class _AppShim:
    _update_sxfy_filters = Gem300DesktopApp._update_sxfy_filters

    def __init__(self) -> None:
        self.settings = {"sxfy_selected_filters": ["S1F1"]}
        self.sxfy_types = ["S1F1", "S6F11"]
        self.sxfy_filter_vars = {"S1F1": _BoolVar(False), "S6F11": _BoolVar(False)}
        self.menu_rebuilt = False

    def _build_sxfy_menu(self) -> None:
        self.menu_rebuilt = True


def _entry(message: str, line_no: int) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 14, 12, 0, line_no),
        log_type=LogType.SECS,
        source_file="secs.log",
        message=message,
        line_no=line_no,
    )


def test_update_sxfy_filters_selects_all_for_new_analysis() -> None:
    original = desktop_app.BooleanVar
    desktop_app.BooleanVar = _BoolVar
    try:
        app = _AppShim()
        Gem300DesktopApp._update_sxfy_filters(
            app,
            [_entry("S1F1 W", 1), _entry("S6F11 W", 2)],
        )
    finally:
        desktop_app.BooleanVar = original

    assert app.sxfy_types == ["S1F1", "S6F11"]
    assert {key: var.get() for key, var in app.sxfy_filter_vars.items()} == {
        "S1F1": True,
        "S6F11": True,
    }
    assert app.menu_rebuilt is True


if __name__ == "__main__":
    test_update_sxfy_filters_selects_all_for_new_analysis()
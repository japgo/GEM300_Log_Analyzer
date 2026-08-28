from __future__ import annotations

import sys
import threading
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import desktop_app
from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _AppShim:
    _keyword_cache_signature = staticmethod(Gem300DesktopApp._keyword_cache_signature)
    _keyword_match_bitmap = Gem300DesktopApp._keyword_match_bitmap
    _clear_keyword_match_cache = Gem300DesktopApp._clear_keyword_match_cache

    def __init__(self) -> None:
        self._keyword_match_cache = OrderedDict()
        self._keyword_match_cache_bytes = 0
        self._keyword_match_cache_signature = None
        self._keyword_match_cache_lock = threading.Lock()

    @staticmethod
    def _entry_key(entry: LogEntry) -> str:
        return f"{entry.source_file}|{entry.line_no}|{entry.timestamp.isoformat()}"

    @staticmethod
    def _entry_sxfy_type(_entry: LogEntry) -> str | None:
        return None


def _entry(message: str, line_no: int) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 2, 12, 0, line_no),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=message,
        line_no=line_no,
    )


def test_keyword_filter_result_is_not_reduced_by_navigation_text() -> None:
    entries = [
        _entry("carrier ABC load request", 1),
        _entry("carrier ABC mapping complete needle", 2),
        _entry("unrelated needle alarm", 3),
    ]

    filtered_entries, _matches, matched_keywords = (
        Gem300DesktopApp._build_filtered_entries(
            _AppShim(),
            entries,
            [("AND", "carrier ABC")],
            [],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            set(),
            False,
            False,
        )
    )

    assert [entry.line_no for entry in filtered_entries] == [1, 2]
    assert matched_keywords[id(entries[0])] == "carrier ABC"
    assert matched_keywords[id(entries[1])] == "carrier ABC"


def test_bookmarks_can_bypass_include_and_exclude_keywords() -> None:
    entries = [
        _entry("target normal", 1),
        _entry("unrelated bookmarked", 2),
        _entry("target DEBUG bookmarked", 3),
        _entry("unrelated normal", 4),
    ]
    bookmarked_keys = {
        _AppShim._entry_key(entries[1]),
        _AppShim._entry_key(entries[2]),
    }

    filtered_entries, _matches, matched_keywords = (
        Gem300DesktopApp._build_filtered_entries(
            _AppShim(),
            entries,
            [("AND", "target")],
            ["DEBUG"],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            bookmarked_keys,
            False,
            False,
            always_include_bookmarks=True,
        )
    )

    assert [entry.line_no for entry in filtered_entries] == [1, 2, 3]
    assert matched_keywords[id(entries[0])] == "target"
    assert id(entries[1]) not in matched_keywords
    assert id(entries[2]) not in matched_keywords


def test_bookmark_keyword_exception_is_not_affected_by_navigation_search() -> None:
    entries = [
        _entry("unrelated bookmarked needle", 1),
        _entry("unrelated bookmarked", 2),
    ]
    bookmarked_keys = {_AppShim._entry_key(entry) for entry in entries}

    filtered_entries, _matches, _matched_keywords = (
        Gem300DesktopApp._build_filtered_entries(
            _AppShim(),
            entries,
            [("AND", "target")],
            [],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            bookmarked_keys,
            False,
            False,
            True,
        )
    )

    assert [entry.line_no for entry in filtered_entries] == [1, 2]


def test_keyword_bitmap_is_reused_until_analysis_entries_change() -> None:
    app = _AppShim()
    entries = [_entry("target first", 1), _entry("other", 2)]

    with patch(
        "desktop_app.build_keyword_match_bitmap",
        wraps=desktop_app.build_keyword_match_bitmap,
    ) as build_bitmap:
        first, _matches, _keywords = Gem300DesktopApp._build_filtered_entries(
            app,
            entries,
            [("AND", "target")],
            [],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            set(),
            False,
            False,
        )
        second, _matches, _keywords = Gem300DesktopApp._build_filtered_entries(
            app,
            entries,
            [("AND", "target")],
            [],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            set(),
            False,
            False,
        )

    assert [entry.line_no for entry in first] == [1]
    assert [entry.line_no for entry in second] == [1]
    assert build_bitmap.call_count == 1


def test_cache_combines_and_or_exclude_without_rescanning_cached_terms() -> None:
    app = _AppShim()
    entries = [
        _entry("carrier ready", 1),
        _entry("S6F11 event", 2),
        _entry("carrier DEBUG", 3),
        _entry("unrelated", 4),
    ]

    with patch(
        "desktop_app.build_keyword_match_bitmap",
        wraps=desktop_app.build_keyword_match_bitmap,
    ) as build_bitmap:
        filtered, _matches, matched = Gem300DesktopApp._build_filtered_entries(
            app,
            entries,
            [("AND", "carrier"), ("OR", "S6F11")],
            ["DEBUG"],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            set(),
            False,
            False,
        )
        Gem300DesktopApp._build_filtered_entries(
            app,
            entries,
            [("OR", "S6F11"), ("OR", "carrier")],
            ["DEBUG"],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            set(),
            False,
            False,
        )

    assert [entry.line_no for entry in filtered] == [1, 2]
    assert matched[id(entries[0])] == "carrier"
    assert matched[id(entries[1])] == "S6F11"
    assert build_bitmap.call_count == 3


def test_keyword_cache_is_invalidated_when_analysis_entries_change() -> None:
    app = _AppShim()
    first_entries = [_entry("target", 1), _entry("other", 2)]
    next_entries = [_entry("other", 3), _entry("target", 4)]

    first_bitmap = app._keyword_match_bitmap(first_entries, "target", False, False)
    next_bitmap = app._keyword_match_bitmap(next_entries, "target", False, False)

    assert list(first_bitmap) == [1, 0]
    assert list(next_bitmap) == [0, 1]
    assert len(app._keyword_match_cache) == 1


def test_filter_build_stops_when_cancel_is_requested() -> None:
    entries = [_entry("target", index) for index in range(1, 10)]
    cancel_event = threading.Event()
    cancel_event.set()

    with pytest.raises(InterruptedError):
        Gem300DesktopApp._build_filtered_entries(
            _AppShim(),
            entries,
            [("AND", "target")],
            [],
            {"MMI", "SECS"},
            None,
            None,
            None,
            False,
            set(),
            False,
            False,
            cancel_event=cancel_event,
        )


if __name__ == "__main__":
    test_keyword_filter_result_is_not_reduced_by_navigation_text()

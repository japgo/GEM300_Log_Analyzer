from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _AppShim:
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


def test_result_search_filters_current_keyword_result_only() -> None:
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
            "needle",
        )
    )

    assert [entry.line_no for entry in filtered_entries] == [2]
    assert matched_keywords[id(filtered_entries[0])] == "carrier ABC; 결과 내: needle"


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


def test_bookmark_keyword_exception_still_respects_result_search() -> None:
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
            "needle",
            True,
        )
    )

    assert [entry.line_no for entry in filtered_entries] == [1]


if __name__ == "__main__":
    test_result_search_filters_current_keyword_result_only()

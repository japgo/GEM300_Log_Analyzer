from __future__ import annotations

import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _TimeShim:
    _parse_time_filter_input = staticmethod(Gem300DesktopApp._parse_time_filter_input)

    def _default_time_filter_date(self):
        return date(2026, 7, 2)


class _FilterShim:
    @staticmethod
    def _entry_key(entry: LogEntry) -> str:
        return f"{entry.source_file}|{entry.line_no}|{entry.timestamp.isoformat()}"

    @staticmethod
    def _entry_sxfy_type(_entry: LogEntry) -> str | None:
        return None


def _entry(hour: int, minute: int, line_no: int) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 2, hour, minute, 0),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=f"log {line_no}",
        line_no=line_no,
    )


def test_parse_custom_time_filter_accepts_time_only() -> None:
    start, end = Gem300DesktopApp._parse_custom_time_filter_inputs(
        _TimeShim(), "12:00:00", "12:30:00"
    )

    assert start == datetime(2026, 7, 2, 12, 0, 0)
    assert end == datetime(2026, 7, 2, 12, 30, 0)


def test_parse_custom_time_filter_allows_midnight_crossing_for_time_only() -> None:
    start, end = Gem300DesktopApp._parse_custom_time_filter_inputs(
        _TimeShim(), "23:50", "00:10"
    )

    assert start == datetime(2026, 7, 2, 23, 50, 0)
    assert end == datetime(2026, 7, 3, 0, 10, 0)


def test_build_filtered_entries_applies_custom_time_window() -> None:
    entries = [_entry(11, 59, 1), _entry(12, 0, 2), _entry(12, 30, 3)]

    filtered_entries, _matches, _matched_keywords = (
        Gem300DesktopApp._build_filtered_entries(
            _FilterShim(),
            entries,
            [],
            [],
            {"MMI", "SECS"},
            None,
            datetime(2026, 7, 2, 12, 0, 0),
            datetime(2026, 7, 2, 12, 10, 0),
            False,
            set(),
            False,
            False,
        )
    )

    assert [entry.line_no for entry in filtered_entries] == [2]


if __name__ == "__main__":
    test_parse_custom_time_filter_accepts_time_only()
    test_parse_custom_time_filter_allows_midnight_crossing_for_time_only()
    test_build_filtered_entries_applies_custom_time_window()

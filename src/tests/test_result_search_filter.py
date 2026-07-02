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


if __name__ == "__main__":
    test_result_search_filters_current_keyword_result_only()

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


def _entry(message: str, line_no: int) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 9, 12, 0, line_no),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=message,
        line_no=line_no,
    )


def test_format_entries_for_clipboard_separates_logs_with_blank_line() -> None:
    text = Gem300DesktopApp._format_entries_for_clipboard(
        [_entry("first log", 1), _entry("second\nlog", 2), _entry("third log", 3)]
    )

    assert text == "first log\n\nsecond\nlog\n\nthird log"


if __name__ == "__main__":
    test_format_entries_for_clipboard_separates_logs_with_blank_line()

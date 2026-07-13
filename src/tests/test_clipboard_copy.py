from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


def _entry(message: str, line_no: int, raw_line: str = "") -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 9, 12, 0, line_no),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=message,
        line_no=line_no,
        raw_line=raw_line,
    )


def test_format_entries_for_clipboard_uses_raw_lines_with_blank_separator() -> None:
    text = Gem300DesktopApp._format_entries_for_clipboard(
        [
            _entry(
                "first log",
                1,
                "2026-07-09 12:00:00:001|1|1|first log",
            ),
            _entry(
                "second\ncontinuation",
                2,
                "2026-07-09 12:00:00:002|1|2|second\ncontinuation",
            ),
            _entry("third log", 3, "2026-07-09 12:00:00:003|1|3|third log"),
        ]
    )

    assert (
        text
        == "2026-07-09 12:00:00:001|1|1|first log\n\n"
        "2026-07-09 12:00:00:002|1|2|second\ncontinuation\n\n"
        "2026-07-09 12:00:00:003|1|3|third log"
    )


def test_format_entries_for_clipboard_falls_back_to_message() -> None:
    text = Gem300DesktopApp._format_entries_for_clipboard([_entry("message only", 1)])

    assert text == "message only"


def test_format_entries_for_clipboard_keeps_time_prefix_with_annotations() -> None:
    text = Gem300DesktopApp._format_entries_for_clipboard(
        [
            _entry(
                "S6F11 W\n"
                "  <U4 [1] 777> // (CEID 777) Carrier Arrived\n"
                "  <A [7] CARR001> // (1001) CarrierID",
                10,
                "10:00:10:001: [1] S6F11 W\n"
                "  <U4 [1] 777>\n"
                "  <A [7] CARR001>",
            )
        ]
    )

    assert text == (
        "10:00:10:001: [1] S6F11 W\n"
        "  <U4 [1] 777> // (CEID 777) Carrier Arrived\n"
        "  <A [7] CARR001> // (1001) CarrierID"
    )


if __name__ == "__main__":
    test_format_entries_for_clipboard_uses_raw_lines_with_blank_separator()
    test_format_entries_for_clipboard_falls_back_to_message()
    test_format_entries_for_clipboard_keeps_time_prefix_with_annotations()
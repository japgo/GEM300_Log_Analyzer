from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from gem300_log_analyzer.analysis.alarm_summary import extract_alarms, is_alarm_entry
from gem300_log_analyzer.models import LogEntry, LogType


def _entry(
    message: str,
    *,
    level_name: str | None = None,
    color_index: int | None = None,
) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 6, 30, 12, 0, 0),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=message,
        line_no=1,
        level_name=level_name,
        color_index=color_index,
    )


def test_is_alarm_entry_matches_extract_alarms_inputs() -> None:
    entries = [
        _entry("plain status"),
        _entry("level based", level_name="Alarm"),
        _entry("color based", color_index=31),
        _entry("[ALARM] tagged message"),
        _entry("Alarm Code [1234] message"),
    ]

    alarms = extract_alarms(entries)

    assert [is_alarm_entry(entry) for entry in entries] == [
        False,
        True,
        True,
        True,
        True,
    ]
    assert len(alarms) == 4
    assert alarms[-1].alarm_code == "1234"


if __name__ == "__main__":
    test_is_alarm_entry_matches_extract_alarms_inputs()

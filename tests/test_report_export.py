from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from gem300_log_analyzer.export.report_export import generate_report
from gem300_log_analyzer.models import (
    AlarmRecord,
    Gem300Event,
    LogEntry,
    LogType,
    SearchMatch,
)


def test_report_includes_scoped_investigation_hints() -> None:
    normal = LogEntry(
        timestamp=datetime(2026, 6, 30, 10, 0, 0, 100000),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message="CarrierObject::StateChange CARRIER_ID=LOT01",
        line_no=1,
        level_name="Normal",
        ceid=101,
        event_name="Carrier Arrived",
    )
    precursor = LogEntry(
        timestamp=datetime(2026, 6, 30, 10, 0, 0, 600000),
        log_type=LogType.SECS,
        source_file="secs.log",
        message="S2F41 START command before failure CARRIER_ID=LOT01",
        line_no=10,
        level_name=None,
        ceid=777,
        event_name="Start Command",
    )
    recovery = LogEntry(
        timestamp=datetime(2026, 6, 30, 10, 0, 2, 0),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message="Operator checked load port after alarm",
        line_no=3,
        level_name="Info",
    )
    fail = LogEntry(
        timestamp=datetime(2026, 6, 30, 10, 0, 1, 200000),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message="[ALARM] Alarm Code [3001] Load port failed to clamp",
        line_no=2,
        level_name="Alarm",
        ceid=3001,
        event_name="Clamp Failed",
    )
    alarm = AlarmRecord(
        timestamp=fail.timestamp,
        alarm_code="3001",
        message="Load port failed to clamp",
        source_file="mmi.log",
        line_no=2,
        level_name="Alarm",
    )
    outside_alarm = AlarmRecord(
        timestamp=datetime(2026, 6, 30, 10, 5, 0, 0),
        alarm_code="9999",
        message="Outside filtered report scope",
        source_file="mmi.log",
        line_no=99,
        level_name="Alarm",
    )
    event = Gem300Event(
        timestamp=normal.timestamp,
        event_type="CarrierObject::StateChange",
        object_name="CarrierObject",
        details="CARRIER_ID=LOT01",
        source_file="mmi.log",
        line_no=1,
        raw_message=normal.message,
    )
    outside_event = Gem300Event(
        timestamp=datetime(2026, 6, 30, 10, 6, 0, 0),
        event_type="LoadPortObject::StateChange",
        object_name="LoadPortObject",
        details="Outside filtered report scope",
        source_file="mmi.log",
        line_no=100,
        raw_message="Outside filtered report scope",
    )
    outside_entry = LogEntry(
        timestamp=datetime(2026, 6, 30, 10, 7, 0, 0),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message="Outside filtered keyword scope",
        line_no=101,
        level_name="Normal",
    )
    match = SearchMatch(entry=fail, matched_text="failed", keyword="failed")
    outside_match = SearchMatch(
        entry=outside_entry,
        matched_text="outside",
        keyword="outside",
    )

    report = generate_report(
        [normal, precursor, fail, recovery],
        [event, outside_event],
        [alarm, outside_alarm],
        [match, outside_match],
        keyword="failed",
    )

    assert "## Investigation Hints" in report
    assert "## Problem Context" in report
    assert "First alarm: 2026-06-30 10:00:01:200 code=3001" in report
    assert "First Fail/Alarm log: 2026-06-30 10:00:01:200 [MMI] mmi.log:2" in report
    assert "Top CEID/Event: CEID 101 (Carrier Arrived): 1x; CEID 777 (Start Command): 1x; CEID 3001 (Clamp Failed): 1x" in report
    assert "Pre-problem signals: CEID 101 (Carrier Arrived); Carrier LOT01; CEID 777 (Start Command); SxFy S2F41" in report
    assert "Top matched keywords: failed: 1x" in report
    assert "before: 2026-06-30 10:00:00:600 +500ms | [SECS] secs.log:10" in report
    assert "CENTER: 2026-06-30 10:00:01:200 +600ms | [MMI] mmi.log:2" in report
    assert "after: 2026-06-30 10:00:02:000 +800ms | [MMI] mmi.log:3" in report
    assert "Total alarm events: 1" in report
    assert "Total GEM300 events: 1" in report
    assert "CARRIER_ID=LOT01" in report
    assert "9999" not in report
    assert "outside: 1x" not in report
    assert "Outside filtered keyword scope" not in report
    assert "Outside filtered report scope" not in report


def test_report_keeps_empty_report_scope() -> None:
    outside_entry = LogEntry(
        timestamp=datetime(2026, 6, 30, 11, 0, 0, 0),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message="Outside empty report scope",
        line_no=20,
        level_name="Alarm",
    )
    outside_alarm = AlarmRecord(
        timestamp=outside_entry.timestamp,
        alarm_code="4001",
        message="Outside empty report scope",
        source_file="mmi.log",
        line_no=20,
        level_name="Alarm",
    )
    outside_match = SearchMatch(
        entry=outside_entry,
        matched_text="outside",
        keyword="outside",
    )

    report = generate_report(
        [],
        [],
        [outside_alarm],
        [outside_match],
        keyword="outside",
    )

    assert "Total parsed entries: 0" in report
    assert "No entries available for investigation hints." in report
    assert "No alarms detected in the reported entries." in report
    assert "No matches for: outside" in report
    assert "Outside empty report scope" not in report
    assert "4001" not in report


if __name__ == "__main__":
    test_report_includes_scoped_investigation_hints()
    test_report_keeps_empty_report_scope()

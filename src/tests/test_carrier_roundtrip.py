from datetime import datetime, timedelta

from gem300_log_analyzer.analysis.carrier_roundtrip import build_carrier_roundtrip
from gem300_log_analyzer.analysis.gem300_trace import extract_gem300_events
from gem300_log_analyzer.models import AlarmRecord, LogEntry, LogType


def _entry(second: int, message: str, line_no: int, log_type: LogType = LogType.MMI) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 7, 1, 8, 0, second),
        log_type=log_type,
        source_file="mmi.log" if log_type == LogType.MMI else "secs.log",
        message=message,
        line_no=line_no,
    )


def test_build_carrier_roundtrip_orders_rows_and_keeps_entry_refs() -> None:
    entries = [
        _entry(
            1,
            "CarrierObject::StateChange model=Arrived, GetString()=Carrier idx: 1, CARRIER_ID: LOT01, CARRIERID_READ: YES, SLOTMAP_READ: NO",
            10,
        ),
        _entry(
            2,
            "LoadPortObject::StateChange model=Present, GetString()=PorNo: 1, LocID: LP1",
            11,
        ),
        _entry(
            5,
            "CarrierObject::StateChange model=Ready, GetString()=Carrier idx: 1, CARRIER_ID: LOT01, CARRIERID_READ: YES, SLOTMAP_READ: YES",
            12,
        ),
        _entry(
            8,
            "CarrierObject::ClearCarrierInfo Before Clear, this->CarrierID : LOT01, SEQPortNo : 1, MMIPortNo : 1",
            13,
        ),
        _entry(9, "S6F11 CEID=202 Carrier LOT01 completed", 20, LogType.SECS),
    ]
    events = extract_gem300_events(entries)
    rows = build_carrier_roundtrip("LOT01", entries, events, [])

    assert [row.line_no for row in rows] == [10, 11, 12, 13, 20]
    assert rows[0].state == "Carrier ID Read"
    assert rows[0].level == "WARN"
    assert rows[2].state == "Carrier ID / Slot Map Read"
    assert rows[3].state == "Carrier Released"
    assert rows[4].state == "Carrier Related Log"
    assert all(row.entry is not None for row in rows)
    assert rows[1].port_no == "1"
    assert rows[1].gap_ms == 1000


def test_build_carrier_roundtrip_includes_window_alarm() -> None:
    entries = [
        _entry(
            1,
            "CarrierObject::StateChange model=Ready, GetString()=Carrier idx: 1, CARRIER_ID: LOT01, CARRIERID_READ: YES, SLOTMAP_READ: YES",
            10,
        ),
        _entry(
            20,
            "CarrierObject::ClearCarrierInfo Before Clear, this->CarrierID : LOT01, SEQPortNo : 1, MMIPortNo : 1",
            11,
        ),
        _entry(12, "[ALARM] Clamp Failed", 12),
    ]
    events = extract_gem300_events(entries)
    alarms = [
        AlarmRecord(
            timestamp=entries[2].timestamp,
            alarm_code="3001",
            message="Clamp Failed",
            source_file="mmi.log",
            line_no=12,
        )
    ]

    rows = build_carrier_roundtrip(
        "LOT01",
        entries,
        events,
        alarms,
        context=timedelta(seconds=1),
    )

    alarm_rows = [row for row in rows if row.state == "Alarm"]
    assert len(alarm_rows) == 1
    assert alarm_rows[0].level == "ERROR"
    assert alarm_rows[0].entry is entries[2]

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from gem300_log_analyzer.models import AlarmRecord, Gem300Event, LogEntry


@dataclass
class CarrierRoundtripRow:
    timestamp: datetime
    gap_ms: Optional[int]
    port_no: Optional[str]
    level: str
    state: str
    detail: str
    source: str
    source_file: str
    line_no: int
    entry: Optional[LogEntry] = None
    event: Optional[Gem300Event] = None
    alarm: Optional[AlarmRecord] = None

    @property
    def display_time(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3]


def build_carrier_roundtrip(
    carrier_id: str,
    entries: Iterable[LogEntry],
    gem300_events: Iterable[Gem300Event],
    alarms: Iterable[AlarmRecord],
    context: timedelta = timedelta(minutes=5),
) -> list[CarrierRoundtripRow]:
    target = carrier_id.strip()
    if not target:
        return []
    target_key = target.lower()
    entry_list = list(entries)
    event_list = list(gem300_events)
    alarm_list = list(alarms)
    entry_by_location = {(entry.source_file, entry.line_no): entry for entry in entry_list}

    seed_events = [
        event
        for event in event_list
        if _matches_carrier(event.carrier_id, target_key)
        or target_key in event.details.lower()
        or target_key in event.raw_message.lower()
    ]
    direct_entries = [entry for entry in entry_list if target_key in entry.message.lower()]

    if not seed_events and not direct_entries:
        return []

    seed_times = [event.timestamp for event in seed_events] + [entry.timestamp for entry in direct_entries]
    start = min(seed_times)
    end = max(seed_times)
    window_start = start - context
    window_end = end + context

    ports = {
        value
        for event in seed_events
        for value in (event.port_no, event.seq_port_no, event.mmi_port_no)
        if value
    }

    rows: list[CarrierRoundtripRow] = []
    seen: set[tuple[str, str, int, datetime]] = set()

    def add_row(row: CarrierRoundtripRow) -> None:
        key = (row.source, row.source_file, row.line_no, row.timestamp)
        if key in seen:
            return
        seen.add(key)
        rows.append(row)

    for event in event_list:
        include = event in seed_events
        if not include and event.event_type == "LoadPortObject::StateChange":
            include = bool(ports) and event.port_no in ports and window_start <= event.timestamp <= window_end
        if not include:
            continue
        entry = entry_by_location.get((event.source_file, event.line_no))
        add_row(_row_from_event(event, entry))

    for alarm in alarm_list:
        if not (window_start <= alarm.timestamp <= window_end):
            continue
        if target_key not in alarm.message.lower() and not (start <= alarm.timestamp <= end):
            continue
        entry = entry_by_location.get((alarm.source_file, alarm.line_no))
        add_row(_row_from_alarm(alarm, entry))

    for entry in direct_entries:
        if (entry.source_file, entry.line_no) in {
            (row.source_file, row.line_no) for row in rows
        }:
            continue
        add_row(
            CarrierRoundtripRow(
                timestamp=entry.timestamp,
                gap_ms=None,
                port_no=None,
                level="OK",
                state=_entry_state(entry),
                detail=entry.message.strip()[:500],
                source=entry.log_type.value,
                source_file=entry.source_file,
                line_no=entry.line_no,
                entry=entry,
            )
        )

    rows.sort(key=lambda row: (row.timestamp, row.source_file, row.line_no))
    previous: Optional[CarrierRoundtripRow] = None
    for row in rows:
        if previous is None:
            row.gap_ms = None
        else:
            row.gap_ms = int(round((row.timestamp - previous.timestamp).total_seconds() * 1000))
            if row.level == "OK" and row.gap_ms >= 30_000:
                row.level = "WARN"
        previous = row
    return rows


def _matches_carrier(value: Optional[str], target_key: str) -> bool:
    return bool(value) and value.strip().lower() == target_key


def _row_from_event(event: Gem300Event, entry: Optional[LogEntry]) -> CarrierRoundtripRow:
    level = "OK"
    if (event.id_read or "").upper() == "NO" or (event.slotmap_read or "").upper() == "NO":
        level = "WARN"
    state = _event_state(event)
    return CarrierRoundtripRow(
        timestamp=event.timestamp,
        gap_ms=None,
        port_no=event.port_no or event.mmi_port_no or event.seq_port_no,
        level=level,
        state=state,
        detail=event.details,
        source=entry.log_type.value if entry else "MMI",
        source_file=event.source_file,
        line_no=event.line_no,
        entry=entry,
        event=event,
    )


def _row_from_alarm(alarm: AlarmRecord, entry: Optional[LogEntry]) -> CarrierRoundtripRow:
    detail = alarm.message
    if alarm.alarm_code:
        detail = f"Alarm Code={alarm.alarm_code}, {detail}"
    return CarrierRoundtripRow(
        timestamp=alarm.timestamp,
        gap_ms=None,
        port_no=None,
        level="ERROR",
        state="Alarm",
        detail=detail,
        source=entry.log_type.value if entry else "MMI",
        source_file=alarm.source_file,
        line_no=alarm.line_no,
        entry=entry,
        alarm=alarm,
    )


def _event_state(event: Gem300Event) -> str:
    if event.event_type == "CarrierObject::StateChange":
        if (event.id_read or "").upper() == "YES" and (event.slotmap_read or "").upper() == "YES":
            return "Carrier ID / Slot Map Read"
        if (event.id_read or "").upper() == "YES":
            return "Carrier ID Read"
        return "Carrier StateChange"
    if event.event_type == "CarrierObject::ClearCarrierInfo":
        return "Carrier Released"
    if event.event_type == "LoadPortObject::StateChange":
        return "LoadPort StateChange"
    if event.event_type == "[CMS]":
        return "CMS Event"
    if event.event_type == "DeletejobList":
        return "Job Deleted"
    return event.event_type


def _entry_state(entry: LogEntry) -> str:
    if entry.ceid is not None:
        if entry.event_name:
            return f"CEID {entry.ceid} {entry.event_name}"
        return f"CEID {entry.ceid}"
    return "Carrier Related Log"

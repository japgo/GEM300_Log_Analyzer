from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Optional

from gem300_log_analyzer.models import Gem300Event, LogEntry

CARRIER_STATE_RE = re.compile(
    r"CarrierObject::StateChange model=(?P<model>\w+), GetString\(\)="
    r"Carrier idx: (?P<idx>\d+), CARRIER_ID: (?P<carrier_id>[^,]+),"
    r" CARRIERID_READ: (?P<id_read>\w+), SLOTMAP_READ: (?P<slot_read>\w+)",
    re.I,
)
CLEAR_CARRIER_RE = re.compile(
    r"CarrierObject::ClearCarrierInfo Before Clear, "
    r"this->CarrierID : (?P<carrier_id>[^,]*), "
    r"SEQPortNo : (?P<seq_port>\d+), MMIPortNo : (?P<mmi_port>\d+)",
    re.I,
)
LOADPORT_STATE_RE = re.compile(
    r"LoadPortObject::StateChange model=(?P<model>\w+), GetString\(\)="
    r"PorNo: (?P<port>\d+), LocID: (?P<loc>\w+)",
    re.I,
)
SUBSTRATE_INIT_RE = re.compile(
    r"SubstrateObject::Initialize substrateno=(?P<no>\d+), "
    r"SubstrateID=(?P<sub_id>[^,]+), AcquiredID=(?P<acq_id>[^,\s]+)",
    re.I,
)
CMS_EVENT_RE = re.compile(r"\[CMS\]\s*(?P<detail>.+)", re.I)
DELETE_JOB_RE = re.compile(r"DeletejobList|DeleteJobList", re.I)

GEM300_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("CarrierObject::StateChange", CARRIER_STATE_RE),
    ("CarrierObject::ClearCarrierInfo", CLEAR_CARRIER_RE),
    ("LoadPortObject::StateChange", LOADPORT_STATE_RE),
    ("SubstrateObject::Initialize", SUBSTRATE_INIT_RE),
    ("[CMS]", CMS_EVENT_RE),
    ("DeletejobList", DELETE_JOB_RE),
]


def extract_gem300_events(entries: Iterable[LogEntry]) -> list[Gem300Event]:
    events: list[Gem300Event] = []

    for entry in entries:
        if entry.log_type.value != "MMI":
            continue
        msg = entry.message

        for event_type, pattern in GEM300_PATTERNS:
            match = pattern.search(msg)
            if not match:
                continue

            model = carrier_idx = port_no = substrate_no = None
            details = msg

            if event_type == "CarrierObject::StateChange":
                model = match.group("model")
                carrier_idx = match.group("idx")
                details = (
                    f"model={model}, idx={carrier_idx}, "
                    f"CARRIER_ID={match.group('carrier_id').strip()}, "
                    f"CARRIERID_READ={match.group('id_read')}, "
                    f"SLOTMAP_READ={match.group('slot_read')}"
                )
            elif event_type == "CarrierObject::ClearCarrierInfo":
                details = (
                    f"CarrierID={match.group('carrier_id').strip()}, "
                    f"SEQPortNo={match.group('seq_port')}, "
                    f"MMIPortNo={match.group('mmi_port')}"
                )
            elif event_type == "LoadPortObject::StateChange":
                model = match.group("model")
                port_no = match.group("port")
                details = (
                    f"model={model}, PorNo={port_no}, LocID={match.group('loc')}"
                )
            elif event_type == "SubstrateObject::Initialize":
                substrate_no = match.group("no")
                details = (
                    f"substrateno={substrate_no}, "
                    f"SubstrateID={match.group('sub_id').strip()}, "
                    f"AcquiredID={match.group('acq_id').strip()}"
                )
            elif event_type == "[CMS]":
                details = match.group("detail").strip()
            elif event_type == "DeletejobList":
                details = msg.strip()

            object_name = event_type.split("::")[0] if "::" in event_type else event_type

            events.append(
                Gem300Event(
                    timestamp=entry.timestamp,
                    event_type=event_type,
                    object_name=object_name,
                    details=details,
                    source_file=entry.source_file,
                    line_no=entry.line_no,
                    raw_message=msg,
                    model=model,
                    carrier_idx=carrier_idx,
                    port_no=port_no,
                    substrate_no=substrate_no,
                )
            )
            break

    return events


def filter_events_by_time(
    events: Iterable[Gem300Event],
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[Gem300Event]:
    result: list[Gem300Event] = []
    for event in events:
        if start and event.timestamp < start:
            continue
        if end and event.timestamp > end:
            continue
        result.append(event)
    return result

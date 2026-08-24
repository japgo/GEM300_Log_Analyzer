from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class LogType(str, Enum):
    MMI = "MMI"
    SECS = "SECS"
    UNKNOWN = "UNKNOWN"


@dataclass
class LogEntry:
    timestamp: datetime
    log_type: LogType
    source_file: str
    message: str
    line_no: int
    color_index: Optional[int] = None
    seq_index: Optional[int] = None
    level_name: Optional[str] = None
    channel: Optional[int] = None
    secs_message: Optional[str] = None
    ceid: Optional[int] = None
    event_name: Optional[str] = None
    is_setup_dump: bool = False
    repeat_count: Optional[int] = None
    raw_line: str = ""
    timeline_index: Optional[int] = None

    @property
    def display_time(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3]


@dataclass
class Gem300Event:
    timestamp: datetime
    event_type: str
    object_name: str
    details: str
    source_file: str
    line_no: int
    raw_message: str
    model: Optional[str] = None
    carrier_idx: Optional[str] = None
    carrier_id: Optional[str] = None
    id_read: Optional[str] = None
    slotmap_read: Optional[str] = None
    port_no: Optional[str] = None
    seq_port_no: Optional[str] = None
    mmi_port_no: Optional[str] = None
    loc_id: Optional[str] = None
    substrate_no: Optional[str] = None


@dataclass
class AlarmRecord:
    timestamp: datetime
    alarm_code: Optional[str]
    message: str
    source_file: str
    line_no: int
    repeat_count: Optional[int] = None
    level_name: str = "Alarm"


@dataclass
class SearchMatch:
    entry: LogEntry
    matched_text: str
    keyword: str = ""


@dataclass
class AnalysisResult:
    entries: list[LogEntry] = field(default_factory=list)
    gem300_events: list[Gem300Event] = field(default_factory=list)
    alarms: list[AlarmRecord] = field(default_factory=list)
    search_matches: list[SearchMatch] = field(default_factory=list)
    skipped_setup_lines: int = 0
    mmi_count: int = 0
    secs_count: int = 0


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from gem300_log_analyzer.storage.disk_text_store import DiskTextRef, read_disk_text


SCAN_HINTS_READY = 1
SCAN_HINT_ALARM = 2
SCAN_HINT_GEM300_EVENT = 4


class LogType(str, Enum):
    MMI = "MMI"
    SECS = "SECS"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class LogEntry:
    timestamp: datetime
    log_type: LogType
    source_file: str
    message: str = field(repr=False)
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
    raw_line: str = field(default="", repr=False)
    timeline_index: Optional[int] = None
    annotated_message: Optional[str] = None
    text_store_path: Optional[str] = field(default=None, repr=False)
    message_offset: int = field(default=0, repr=False)
    message_length: int = field(default=0, repr=False)
    raw_line_offset: int = field(default=0, repr=False)
    raw_line_length: int = field(default=0, repr=False)
    sxfy_type: Optional[str] = None
    s6f11_rptids: tuple[int, ...] = field(default=(), repr=False)
    scan_hints: int = field(default=0, repr=False)
    message_annotations: tuple[tuple[int, str], ...] = field(
        default=(), repr=False
    )

    def __getattribute__(self, name: str):
        if name in {"message", "raw_line"}:
            inline_value = object.__getattribute__(self, name)
            if inline_value:
                return inline_value
            try:
                path = object.__getattribute__(self, "text_store_path")
                offset = object.__getattribute__(self, f"{name}_offset")
                length = object.__getattribute__(self, f"{name}_length")
            except AttributeError:
                return inline_value
            if path is not None and length > 0:
                return read_disk_text(path, offset, length)
            return inline_value
        return object.__getattribute__(self, name)

    def __getstate__(self) -> tuple:
        return tuple(
            object.__getattribute__(self, name) for name in self.__slots__
        )

    def __setstate__(self, state: tuple) -> None:
        for name, value in zip(self.__slots__, state):
            object.__setattr__(self, name, value)

    @property
    def message_ref(self) -> Optional[DiskTextRef]:
        if self.text_store_path is None:
            return None
        return DiskTextRef(
            self.text_store_path, self.message_offset, self.message_length
        )

    @property
    def raw_line_ref(self) -> Optional[DiskTextRef]:
        if self.text_store_path is None:
            return None
        return DiskTextRef(
            self.text_store_path, self.raw_line_offset, self.raw_line_length
        )

    @property
    def display_time(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3]

    @property
    def display_message(self) -> str:
        if self.annotated_message:
            return self.annotated_message
        message = self.message
        if not self.message_annotations:
            return message
        annotations = dict(self.message_annotations)
        return "\n".join(
            line + annotations.get(index, "")
            for index, line in enumerate(message.splitlines())
        )


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

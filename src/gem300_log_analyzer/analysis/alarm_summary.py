from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Optional

from gem300_log_analyzer.models import AlarmRecord, LogEntry

ALARM_CODE_RE = re.compile(r"Alarm Code \[(\d+)\]", re.I)
ALARM_TAG_RE = re.compile(r"\[ALARM\]\s*(.+)", re.I)


def is_alarm_entry(entry: LogEntry) -> bool:
    return (
        entry.color_index == 31
        or (entry.level_name or "").lower() == "alarm"
        or "[ALARM]" in entry.message.upper()
        or "Alarm Code" in entry.message
    )


def extract_alarms(
    entries: Iterable[LogEntry],
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[AlarmRecord]:
    alarms: list[AlarmRecord] = []

    for entry in entries:
        if start and entry.timestamp < start:
            continue
        if end and entry.timestamp > end:
            continue

        if not is_alarm_entry(entry):
            continue

        code_match = ALARM_CODE_RE.search(entry.message)
        tag_match = ALARM_TAG_RE.search(entry.message)
        alarm_code = code_match.group(1) if code_match else None
        message = tag_match.group(1).strip() if tag_match else entry.message.strip()

        alarms.append(
            AlarmRecord(
                timestamp=entry.timestamp,
                alarm_code=alarm_code,
                message=message,
                source_file=entry.source_file,
                line_no=entry.line_no,
                repeat_count=entry.repeat_count,
                level_name=entry.level_name or "Alarm",
            )
        )

    return alarms


def summarize_alarms(alarms: Iterable[AlarmRecord]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for alarm in alarms:
        key = alarm.alarm_code or alarm.message[:80]
        summary[key] = summary.get(key, 0) + (alarm.repeat_count or 1)
    return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))
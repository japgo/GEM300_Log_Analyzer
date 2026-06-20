from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from gem300_log_analyzer.models import LogEntry, LogType

SECS_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}:\d{3}):\s+\[(?P<channel>\d+)\]\s+(?P<msg>.*)$"
)
SECS_ALT_RE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}:\d{3}):\s+\[(?P<channel>\d+)\]\s*(?P<msg>.*)$"
)
FILENAME_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
CEID_INLINE_RE = re.compile(r"\bCEID\s*=\s*(?P<ceid>\d+)\b", re.I)
SECS_VALUE_RE = re.compile(r"<[A-Z0-9]+\s+\[\d+\]\s+(?P<value>\d+)\s*>")


def _extract_date_from_filename(filename: str) -> Optional[date]:
    match = FILENAME_DATE_RE.search(filename)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y-%m-%d").date()


def _parse_secs_timestamp(ts_text: str, base_date: date) -> datetime:
    time_part = datetime.strptime(ts_text, "%H:%M:%S:%f")
    return datetime.combine(base_date, time_part.time())


def extract_s6f11_ceid(message: str) -> Optional[int]:
    inline = CEID_INLINE_RE.search(message)
    if inline:
        return int(inline.group("ceid"))

    if "S6F11" not in message:
        return None

    values = [int(match.group("value")) for match in SECS_VALUE_RE.finditer(message)]
    if len(values) >= 2:
        # S6F11 body is <L [3]> DATAID, CEID, RPT_LIST.
        return values[1]
    return None


def _finalize_entry(entry: Optional[LogEntry]) -> Optional[LogEntry]:
    if entry is not None:
        entry.ceid = extract_s6f11_ceid(entry.message)
    return entry


def parse_secs_log(
    text: str,
    source_file: str = "",
    base_date: Optional[date] = None,
) -> list[LogEntry]:
    """Parse SECS/GEM communication log text."""
    if base_date is None:
        base_date = _extract_date_from_filename(source_file) or date.today()

    entries: list[LogEntry] = []
    current: Optional[LogEntry] = None

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\n\r")
        if not line.strip():
            continue

        match = SECS_LINE_RE.match(line) or SECS_ALT_RE.match(line)
        if match:
            if current is not None:
                entries.append(_finalize_entry(current))

            ts = _parse_secs_timestamp(match.group("ts"), base_date)
            channel = int(match.group("channel"))
            msg = match.group("msg").strip()

            current = LogEntry(
                timestamp=ts,
                log_type=LogType.SECS,
                source_file=source_file,
                message=msg,
                line_no=line_no,
                channel=channel,
                secs_message=msg,
                raw_line=line,
            )
        elif current is not None and (line.startswith(" ") or line.startswith("\t")):
            current.message = f"{current.message}\n{line.rstrip()}"
            current.secs_message = current.message
        elif current is not None:
            entries.append(_finalize_entry(current))
            current = None

    if current is not None:
        entries.append(_finalize_entry(current))

    return entries


def parse_secs_file(path: Path | str) -> list[LogEntry]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_secs_log(text, source_file=path.name)


def is_secs_content(text: str, filename: str = "") -> bool:
    sample = text[:8000]
    if SECS_LINE_RE.search(sample) or SECS_ALT_RE.search(sample):
        return True
    if re.search(r"\d{4}-\d{2}-\d{2} \d{1,2}\.log", filename):
        return True
    return False

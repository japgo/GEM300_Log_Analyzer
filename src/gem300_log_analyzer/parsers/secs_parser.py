from __future__ import annotations

import re
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Optional

from gem300_log_analyzer.analysis.s6f11_variables import extract_s6f11_rptids
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
DEFAULT_EXCLUDED_S6F11_CEID_RANGES: tuple[tuple[int, int], ...] = ((411001, 411604),)


@lru_cache(maxsize=4096)
def _intern_rptids(rptids: tuple[int, ...]) -> tuple[int, ...]:
    return rptids


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


def is_ceid_excluded(ceid: Optional[int], ranges: Iterable[tuple[int, int]]) -> bool:
    if ceid is None:
        return False
    return any(start <= ceid <= end for start, end in ranges)


def _finalize_entry(
    entry: Optional[LogEntry],
    excluded_s6f11_ceid_ranges: tuple[tuple[int, int], ...],
) -> Optional[LogEntry]:
    if entry is not None:
        message = entry.message
        entry.ceid = extract_s6f11_ceid(message)
        if "S6F11" in message.upper():
            entry.s6f11_rptids = _intern_rptids(
                tuple(sorted(extract_s6f11_rptids(message)))
            )
        if is_ceid_excluded(entry.ceid, excluded_s6f11_ceid_ranges):
            return None
    return entry


def _append_finalized(
    entries: list[LogEntry],
    entry: Optional[LogEntry],
    excluded_s6f11_ceid_ranges: tuple[tuple[int, int], ...],
    entry_callback: Callable[[LogEntry], None] | None = None,
) -> None:
    finalized = _finalize_entry(entry, excluded_s6f11_ceid_ranges)
    if finalized is not None:
        if entry_callback is not None:
            entry_callback(finalized)
        entries.append(finalized)


def parse_secs_log(
    text: str | Iterable[str],
    source_file: str = "",
    base_date: Optional[date] = None,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]] = None,
    cancel_check: Callable[[], bool] | None = None,
    progress_callback: Callable[[int], None] | None = None,
    entry_callback: Callable[[LogEntry], None] | None = None,
) -> list[LogEntry]:
    """Parse SECS/GEM communication log text."""
    if base_date is None:
        base_date = _extract_date_from_filename(source_file) or date.today()
    excluded_ranges = tuple(excluded_s6f11_ceid_ranges or ())

    entries: list[LogEntry] = []
    current: Optional[LogEntry] = None
    current_message_lines: list[str] = []
    current_raw_lines: list[str] = []
    current_is_s6f11 = False
    current_s6f11_value_count = 0

    def materialize_current() -> None:
        if current is None:
            return
        current.message = "\n".join(current_message_lines)
        current.raw_line = "\n".join(current_raw_lines)
        current.secs_message = current.message

    lines = text.splitlines() if isinstance(text, str) else text
    for line_no, raw_line in enumerate(lines, start=1):
        if line_no % 8192 == 0:
            if cancel_check is not None and cancel_check():
                raise InterruptedError("SECS/GEM 로그 분석이 취소되었습니다.")
            if progress_callback is not None:
                progress_callback(line_no)
        line = raw_line.rstrip("\n\r")
        if not line.strip():
            continue

        match = SECS_LINE_RE.match(line) or SECS_ALT_RE.match(line)
        if match:
            if current is not None:
                materialize_current()
                _append_finalized(
                    entries, current, excluded_ranges, entry_callback
                )
            current_is_s6f11 = False
            current_s6f11_value_count = 0

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
            current_message_lines = [msg]
            current_raw_lines = [line]
            current_is_s6f11 = "S6F11" in msg
            inline_ceid = CEID_INLINE_RE.search(msg)
            if inline_ceid:
                current.ceid = int(inline_ceid.group("ceid"))
            if is_ceid_excluded(current.ceid, excluded_ranges):
                current = None
                current_message_lines = []
                current_raw_lines = []
                current_is_s6f11 = False
        elif current is not None and (line.startswith(" ") or line.startswith("\t")):
            raw_continuation = line.rstrip()
            current_message_lines.append(raw_continuation)
            current_raw_lines.append(raw_continuation)
            if current_is_s6f11 and current.ceid is None and excluded_ranges:
                for value_match in SECS_VALUE_RE.finditer(line):
                    current_s6f11_value_count += 1
                    if current_s6f11_value_count == 2:
                        current.ceid = int(value_match.group("value"))
                        if is_ceid_excluded(current.ceid, excluded_ranges):
                            current = None
                            current_message_lines = []
                            current_raw_lines = []
                            current_is_s6f11 = False
                        break
        elif current is not None:
            materialize_current()
            _append_finalized(entries, current, excluded_ranges, entry_callback)
            current = None
            current_message_lines = []
            current_raw_lines = []
            current_is_s6f11 = False
            current_s6f11_value_count = 0

    if current is not None:
        materialize_current()
        _append_finalized(entries, current, excluded_ranges, entry_callback)

    return entries


def parse_secs_file(path: Path | str) -> list[LogEntry]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_secs_log(text, source_file=path.name)


def is_secs_content(text: str, filename: str = "") -> bool:
    sample = text[:8000]
    if SECS_LINE_RE.search(sample) or SECS_ALT_RE.search(sample):
        return True
    if re.search(r"\d{4}-\d{2}-\d{2} \d{1,2}\.(?:log|tslog)$", filename, re.I):
        return True
    return False

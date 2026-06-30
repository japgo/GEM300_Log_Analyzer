from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Optional

from gem300_log_analyzer.models import (
    AlarmRecord,
    AnalysisResult,
    Gem300Event,
    LogEntry,
    SearchMatch,
)


def _fmt_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3]


def _short_message(message: str, limit: int = 120) -> str:
    text = " ".join(message.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _format_time_delta(previous: LogEntry | None, current: LogEntry) -> str:
    if previous is None:
        return ""
    delta = current.timestamp - previous.timestamp
    total_ms = int(delta.total_seconds() * 1000)
    sign = "+" if total_ms >= 0 else "-"
    total_ms = abs(total_ms)
    if total_ms < 1000:
        return f"{sign}{total_ms}ms"

    total_seconds = total_ms / 1000
    if total_seconds < 60:
        text = f"{total_seconds:.1f}".rstrip("0").rstrip(".")
        return f"{sign}{text}s"

    minutes, seconds = divmod(total_ms // 1000, 60)
    return f"{sign}{minutes}m {seconds}s"


def _entry_key(
    timestamp: datetime, source_file: str, line_no: int
) -> tuple[datetime, str, int]:
    return timestamp, source_file, line_no


def _entry_keys(entries: list[LogEntry]) -> set[tuple[datetime, str, int]]:
    return {
        _entry_key(entry.timestamp, entry.source_file, entry.line_no)
        for entry in entries
    }


def _first_problem_entry(entries: list[LogEntry]) -> LogEntry | None:
    for entry in entries:
        level = (entry.level_name or "").lower()
        message = entry.message.lower()
        has_fail_word = re.search(r"\b(?:fail|failed)\b", message) is not None
        if level in {"alarm", "fail"} or "alarm" in message or has_fail_word:
            return entry
    return None


def _problem_entry(
    entries: list[LogEntry], alarms: list[AlarmRecord]
) -> LogEntry | None:
    direct_match = _first_problem_entry(entries)
    if direct_match is not None:
        return direct_match
    if not alarms:
        return None

    first_alarm = min(alarms, key=lambda alarm: alarm.timestamp)
    alarm_key = _entry_key(
        first_alarm.timestamp, first_alarm.source_file, first_alarm.line_no
    )
    for entry in entries:
        if _entry_key(entry.timestamp, entry.source_file, entry.line_no) == alarm_key:
            return entry
    return None


def _problem_context_entries(
    entries: list[LogEntry], center: LogEntry, before: int = 5, after: int = 5
) -> list[tuple[str, LogEntry, str]]:
    try:
        center_index = entries.index(center)
    except ValueError:
        return []

    start = max(0, center_index - before)
    end = min(len(entries), center_index + after + 1)
    rows: list[tuple[str, LogEntry, str]] = []
    for index in range(start, end):
        if index == center_index:
            marker = "CENTER"
        elif index < center_index:
            marker = "before"
        else:
            marker = "after"
        previous = entries[index - 1] if index > 0 else None
        rows.append(
            (marker, entries[index], _format_time_delta(previous, entries[index]))
        )
    return rows


def _top_ceid_event_hints(entries: list[LogEntry], limit: int = 5) -> list[str]:
    counts: Counter[tuple[int, str]] = Counter()
    for entry in entries:
        if entry.ceid is None:
            continue
        counts[(entry.ceid, entry.event_name or "")] += 1

    hints: list[str] = []
    for (ceid, event_name), count in counts.most_common(limit):
        label = f"CEID {ceid}"
        if event_name:
            label += f" ({event_name})"
        hints.append(f"{label}: {count}x")
    return hints


def _top_keyword_hints(search_matches: list[SearchMatch], limit: int = 5) -> list[str]:
    counts: Counter[str] = Counter()
    for match in search_matches:
        for keyword in match.keyword.split(","):
            keyword = keyword.strip()
            if keyword:
                counts[keyword] += 1
    return [f"{keyword}: {count}x" for keyword, count in counts.most_common(limit)]


SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SxFy", re.compile(r"\bS\d+F\d+W?\b", re.I)),
    ("Carrier", re.compile(r"\b(?:CARRIER_ID|CarrierID|CARRIERID)\s*[:=]\s*([^,\s]+)", re.I)),
    ("Substrate", re.compile(r"\b(?:SubstrateID|SubstID)\s*[:=]\s*([^,\s]+)", re.I)),
    ("Acquired", re.compile(r"\bAcquiredID\s*[:=]\s*([^,\s]+)", re.I)),
    ("Port", re.compile(r"\b(?:Port No|PortNo|PorNo|LocID)\s*[:=]\s*([^,\s]+)", re.I)),
)


def _context_signal_summary(entries: list[LogEntry], problem_entry: LogEntry) -> str | None:
    context = _problem_context_entries(entries, problem_entry, before=5, after=0)
    if not context:
        return None

    signals: list[str] = []
    seen: set[str] = set()
    for marker, entry, _time_delta in context:
        if marker != "before":
            continue
        if entry.ceid is not None:
            label = f"CEID {entry.ceid}"
            if entry.event_name:
                label += f" ({entry.event_name})"
            if label not in seen:
                signals.append(label)
                seen.add(label)
        for signal_name, pattern in SIGNAL_PATTERNS:
            for match in pattern.finditer(entry.message):
                value = match.group(0).upper() if signal_name == "SxFy" else match.group(1)
                label = f"{signal_name} {value}"
                if label not in seen:
                    signals.append(label)
                    seen.add(label)
                if len(signals) >= 8:
                    return "; ".join(signals)
    if not signals:
        return None
    return "; ".join(signals)



def _context_gap_summary(entries: list[LogEntry], problem_entry: LogEntry) -> str | None:
    try:
        center_index = entries.index(problem_entry)
    except ValueError:
        return None

    start = max(0, center_index - 5)
    best: tuple[int, LogEntry, LogEntry] | None = None
    for index in range(start + 1, center_index + 1):
        previous = entries[index - 1]
        current = entries[index]
        delta_ms = abs(int((current.timestamp - previous.timestamp).total_seconds() * 1000))
        if best is None or delta_ms > best[0]:
            best = (delta_ms, previous, current)

    if best is None:
        return None

    _delta_ms, previous, current = best
    return (
        f"Largest pre-problem gap: {_format_time_delta(previous, current)} before "
        f"{_fmt_time(current.timestamp)} [{current.log_type.value}] "
        f"{current.source_file}:{current.line_no}"
    )
def _alarms_for_entries(
    entries: list[LogEntry], alarms: list[AlarmRecord]
) -> list[AlarmRecord]:
    if not entries or not alarms:
        return []
    keys = _entry_keys(entries)
    return [
        alarm
        for alarm in alarms
        if _entry_key(alarm.timestamp, alarm.source_file, alarm.line_no) in keys
    ]


def _events_for_entries(
    entries: list[LogEntry], gem300_events: list[Gem300Event]
) -> list[Gem300Event]:
    if not entries or not gem300_events:
        return []
    keys = _entry_keys(entries)
    return [
        event
        for event in gem300_events
        if _entry_key(event.timestamp, event.source_file, event.line_no) in keys
    ]


def _matches_for_entries(
    entries: list[LogEntry], search_matches: list[SearchMatch]
) -> list[SearchMatch]:
    if not entries or not search_matches:
        return []
    keys = _entry_keys(entries)
    return [
        match
        for match in search_matches
        if _entry_key(
            match.entry.timestamp,
            match.entry.source_file,
            match.entry.line_no,
        ) in keys
    ]


def _investigation_hints(
    entries: list[LogEntry],
    alarms: list[AlarmRecord],
    search_matches: list[SearchMatch],
) -> list[str]:
    hints: list[str] = []
    if entries:
        first = entries[0].timestamp
        last = entries[-1].timestamp
        duration = last - first
        hints.append(f"Log span: {_fmt_time(first)} -> {_fmt_time(last)} ({duration})")

    if alarms:
        first_alarm = min(alarms, key=lambda alarm: alarm.timestamp)
        code = f" code={first_alarm.alarm_code}" if first_alarm.alarm_code else ""
        hints.append(
            f"First alarm: {_fmt_time(first_alarm.timestamp)}{code} | "
            f"{_short_message(first_alarm.message)}"
        )

    problem_entry = _problem_entry(entries, alarms)
    if problem_entry is not None:
        hints.append(
            "First Fail/Alarm log: "
            f"{_fmt_time(problem_entry.timestamp)} "
            f"[{problem_entry.log_type.value}] "
            f"{problem_entry.source_file}:{problem_entry.line_no} | "
            f"{problem_entry.level_name or ''} | "
            f"{_short_message(problem_entry.message)}"
        )

    signal_summary = (
        _context_signal_summary(entries, problem_entry)
        if problem_entry is not None
        else None
    )
    if signal_summary:
        hints.append("Pre-problem signals: " + signal_summary)

    gap_summary = (
        _context_gap_summary(entries, problem_entry)
        if problem_entry is not None
        else None
    )
    if gap_summary:
        hints.append(gap_summary)

    ceid_hints = _top_ceid_event_hints(entries)
    if ceid_hints:
        hints.append("Top CEID/Event: " + "; ".join(ceid_hints))

    keyword_hints = _top_keyword_hints(search_matches)
    if keyword_hints:
        hints.append("Top matched keywords: " + "; ".join(keyword_hints))

    if not hints:
        hints.append("No entries available for investigation hints.")
    return hints


def generate_report(
    entries: list[LogEntry],
    gem300_events: list[Gem300Event],
    alarms: list[AlarmRecord],
    search_matches: list[SearchMatch],
    *,
    keyword: str = "",
    skipped_setup_lines: int = 0,
    file_summary: Optional[dict[str, str]] = None,
    format: str = "markdown",
) -> str:
    lines: list[str] = []
    is_md = format.lower() in ("md", "markdown")
    scoped_alarms = _alarms_for_entries(entries, alarms)
    scoped_gem300_events = _events_for_entries(entries, gem300_events)
    scoped_search_matches = _matches_for_entries(entries, search_matches)

    def heading(text: str, level: int = 1) -> None:
        if is_md:
            lines.append(f"{'#' * level} {text}")
        else:
            lines.append(text)
            lines.append("=" * len(text) if level == 1 else "-" * len(text))

    def bullet(text: str) -> None:
        prefix = "- " if is_md else "  * "
        lines.append(f"{prefix}{text}")

    heading("GEM300 Log Analysis Report")
    lines.append("")
    bullet(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    bullet(f"Total parsed entries: {len(entries)}")
    bullet(f"MMI entries: {sum(1 for e in entries if e.log_type.value == 'MMI')}")
    bullet(f"SECS entries: {sum(1 for e in entries if e.log_type.value == 'SECS')}")
    if skipped_setup_lines:
        bullet(f"Skipped Setup.ini dump lines: {skipped_setup_lines}")
    if keyword:
        bullet(f"Search keyword: {keyword}")
    lines.append("")

    if file_summary:
        heading("Uploaded Files", 2)
        for name, log_type in file_summary.items():
            bullet(f"{name} ({log_type})")
        lines.append("")

    heading("Investigation Hints", 2)
    for hint in _investigation_hints(entries, scoped_alarms, scoped_search_matches):
        bullet(hint)
    lines.append("")

    problem_entry = _problem_entry(entries, scoped_alarms)
    if problem_entry is not None:
        heading("Problem Context", 2)
        for marker, entry, time_delta in _problem_context_entries(entries, problem_entry):
            delta_text = f"{time_delta} | " if time_delta else ""
            bullet(
                f"{marker}: {_fmt_time(entry.timestamp)} {delta_text}"
                f"[{entry.log_type.value}] {entry.source_file}:{entry.line_no} | "
                f"{entry.level_name or ''} | {_short_message(entry.message, 160)}"
            )
        lines.append("")

    heading("Alarm Summary", 2)
    if not scoped_alarms:
        bullet("No alarms detected in the reported entries.")
    else:
        bullet(f"Total alarm events: {len(scoped_alarms)}")
        seen: dict[str, int] = {}
        for alarm in scoped_alarms:
            key = alarm.alarm_code or alarm.message[:60]
            seen[key] = seen.get(key, 0) + (alarm.repeat_count or 1)
        for key, count in sorted(seen.items(), key=lambda x: x[1], reverse=True)[:20]:
            bullet(f"[{count}x] {key}")
    lines.append("")

    heading("GEM300 State Timeline", 2)
    if not scoped_gem300_events:
        bullet("No GEM300 events detected in the reported entries.")
    else:
        bullet(f"Total GEM300 events: {len(scoped_gem300_events)}")
        for event in scoped_gem300_events[:200]:
            bullet(
                f"{_fmt_time(event.timestamp)} | {event.event_type} | {event.details}"
            )
        if len(scoped_gem300_events) > 200:
            bullet(f"... and {len(scoped_gem300_events) - 200} more events")
    lines.append("")

    heading("Keyword Search Results", 2)
    if not keyword:
        bullet("No keyword specified.")
    elif not scoped_search_matches:
        bullet(f"No matches for: {keyword}")
    else:
        bullet(f"Matches: {len(scoped_search_matches)}")
        for match in scoped_search_matches[:100]:
            entry = match.entry
            bullet(
                f"{_fmt_time(entry.timestamp)} [{entry.log_type.value}] "
                f"{entry.source_file}:{entry.line_no} - {entry.message[:120]}"
            )
        if len(scoped_search_matches) > 100:
            bullet(f"... and {len(scoped_search_matches) - 100} more matches")

    return "\n".join(lines)


def build_analysis_result(
    entries: list[LogEntry],
    gem300_events: list[Gem300Event],
    alarms: list[AlarmRecord],
    search_matches: list[SearchMatch],
    skipped_setup_lines: int = 0,
) -> AnalysisResult:
    return AnalysisResult(
        entries=entries,
        gem300_events=gem300_events,
        alarms=alarms,
        search_matches=search_matches,
        skipped_setup_lines=skipped_setup_lines,
        mmi_count=sum(1 for e in entries if e.log_type.value == "MMI"),
        secs_count=sum(1 for e in entries if e.log_type.value == "SECS"),
    )

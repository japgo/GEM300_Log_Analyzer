from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from gem300_log_analyzer.models import (
    AlarmRecord,
    AnalysisResult,
    Gem300Event,
    LogEntry,
    SearchMatch,
)


def _fmt_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3]


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

    heading("Alarm Summary", 2)
    if not alarms:
        bullet("No alarms detected.")
    else:
        bullet(f"Total alarm events: {len(alarms)}")
        seen: dict[str, int] = {}
        for alarm in alarms:
            key = alarm.alarm_code or alarm.message[:60]
            seen[key] = seen.get(key, 0) + (alarm.repeat_count or 1)
        for key, count in sorted(seen.items(), key=lambda x: x[1], reverse=True)[:20]:
            bullet(f"[{count}x] {key}")
    lines.append("")

    heading("GEM300 State Timeline", 2)
    if not gem300_events:
        bullet("No GEM300 events detected.")
    else:
        bullet(f"Total GEM300 events: {len(gem300_events)}")
        for event in gem300_events[:200]:
            bullet(
                f"{_fmt_time(event.timestamp)} | {event.event_type} | {event.details}"
            )
        if len(gem300_events) > 200:
            bullet(f"... and {len(gem300_events) - 200} more events")
    lines.append("")

    heading("Keyword Search Results", 2)
    if not keyword:
        bullet("No keyword specified.")
    elif not search_matches:
        bullet(f"No matches for: {keyword}")
    else:
        bullet(f"Matches: {len(search_matches)}")
        for match in search_matches[:100]:
            entry = match.entry
            bullet(
                f"{_fmt_time(entry.timestamp)} [{entry.log_type.value}] "
                f"{entry.source_file}:{entry.line_no} — {entry.message[:120]}"
            )
        if len(search_matches) > 100:
            bullet(f"... and {len(search_matches) - 100} more matches")

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

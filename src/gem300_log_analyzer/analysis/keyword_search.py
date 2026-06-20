from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Optional

from gem300_log_analyzer.models import LogEntry, SearchMatch


def search_keywords(
    entries: Iterable[LogEntry],
    keyword: str,
    case_sensitive: bool = False,
    log_types: Optional[set[str]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[SearchMatch]:
    if not keyword.strip():
        return []

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(keyword, flags)
    except re.error:
        escaped = re.escape(keyword)
        pattern = re.compile(escaped, flags)

    matches: list[SearchMatch] = []
    for entry in entries:
        if log_types and entry.log_type.value not in log_types:
            continue
        if start and entry.timestamp < start:
            continue
        if end and entry.timestamp > end:
            continue

        found = pattern.search(entry.message)
        if found:
            matches.append(SearchMatch(entry=entry, matched_text=found.group(0)))

    return matches

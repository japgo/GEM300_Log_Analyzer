from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Optional

from gem300_log_analyzer.models import LogEntry, SearchMatch


SXFy_WITH_OPTIONAL_W_RE = re.compile(r"\b(S\d+F\d+)W\b", re.IGNORECASE)


def normalize_sxfy_w(text: str) -> str:
    return SXFy_WITH_OPTIONAL_W_RE.sub(lambda match: match.group(1), text)


def _compile_keyword(keyword: str, flags: int, use_regex: bool = False) -> re.Pattern:
    if use_regex:
        try:
            return re.compile(keyword, flags)
        except re.error:
            return re.compile(re.escape(keyword), flags)
    return re.compile(re.escape(keyword), flags)


def search_keywords(
    entries: Iterable[LogEntry],
    keyword: str,
    case_sensitive: bool = False,
    use_regex: bool = False,
    log_types: Optional[set[str]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[SearchMatch]:
    return search_multiple_keywords(
        entries,
        [keyword],
        case_sensitive=case_sensitive,
        use_regex=use_regex,
        log_types=log_types,
        start=start,
        end=end,
    )


def search_multiple_keywords(
    entries: Iterable[LogEntry],
    keywords: Iterable[str],
    or_keywords: Iterable[str] | None = None,
    exclude_keywords: Iterable[str] | None = None,
    match_all: bool = True,
    case_sensitive: bool = False,
    use_regex: bool = False,
    log_types: Optional[set[str]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[SearchMatch]:
    normalized_keywords = [
        normalize_sxfy_w(keyword.strip()) for keyword in keywords if keyword.strip()
    ]
    normalized_or_keywords = [
        normalize_sxfy_w(keyword.strip())
        for keyword in (or_keywords or [])
        if keyword.strip()
    ]
    normalized_exclude_keywords = [
        normalize_sxfy_w(keyword.strip())
        for keyword in (exclude_keywords or [])
        if keyword.strip()
    ]
    if not normalized_keywords and not normalized_or_keywords and not normalized_exclude_keywords:
        return []

    flags = 0 if case_sensitive else re.IGNORECASE
    patterns = [
        (keyword, _compile_keyword(keyword, flags, use_regex))
        for keyword in normalized_keywords
    ]
    or_patterns = [
        (keyword, _compile_keyword(keyword, flags, use_regex))
        for keyword in normalized_or_keywords
    ]
    exclude_patterns = [
        (keyword, _compile_keyword(keyword, flags, use_regex))
        for keyword in normalized_exclude_keywords
    ]

    matches: list[SearchMatch] = []
    for entry in entries:
        if log_types and entry.log_type.value not in log_types:
            continue
        if start and entry.timestamp < start:
            continue
        if end and entry.timestamp > end:
            continue

        search_message = normalize_sxfy_w(entry.message)

        if any(pattern.search(search_message) for _keyword, pattern in exclude_patterns):
            continue

        matched_texts: list[str] = []
        matched_keywords: list[str] = []
        and_matched_count = 0
        for keyword, pattern in patterns:
            found = pattern.search(search_message)
            if found:
                and_matched_count += 1
                matched_keywords.append(keyword)
                matched_texts.append(found.group(0))
        or_matched = False
        for keyword, pattern in or_patterns:
            found = pattern.search(search_message)
            if found:
                or_matched = True
                matched_keywords.append(keyword)
                matched_texts.append(found.group(0))
        and_matched = (
            and_matched_count == len(patterns)
            if match_all
            else bool(patterns and and_matched_count)
        )
        if patterns and or_patterns:
            include_matched = and_matched or or_matched
        elif patterns:
            include_matched = and_matched
        elif or_patterns:
            include_matched = or_matched
        else:
            include_matched = True

        if include_matched:
            matches.append(
                SearchMatch(
                    entry=entry,
                    matched_text=", ".join(matched_texts),
                    keyword=", ".join(matched_keywords),
                )
            )

    return matches

"""Metadata-only CEID/VID enrichment helpers for large timelines."""

from __future__ import annotations

import re
from typing import Callable, Iterable, Mapping, Protocol

from gem300_log_analyzer.analysis.keyword_search import normalize_sxfy_w
from gem300_log_analyzer.models import LogEntry


class ReportVariableLike(Protocol):
    vid: int
    name: str


def collect_reference_ids(
    entries: Iterable[LogEntry],
    *,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[set[int], set[int]]:
    """Collect only identifiers already extracted during the initial parse."""

    ceids: set[int] = set()
    rptids: set[int] = set()
    for index, entry in enumerate(entries):
        if index % 8192 == 0 and cancel_check is not None and cancel_check():
            raise InterruptedError("부가정보 식별자 수집이 취소되었습니다.")
        if entry.ceid is not None:
            ceids.add(entry.ceid)
        rptids.update(entry.s6f11_rptids)
    return ceids, rptids


def build_reference_match_mask(
    entries: list[LogEntry],
    keyword: str,
    event_names: Mapping[int, str] | None,
    report_variables: Mapping[int, list[ReportVariableLike]] | None,
    *,
    case_sensitive: bool = False,
    use_regex: bool = False,
    cancel_check: Callable[[], bool] | None = None,
) -> int:
    """Match lazy CEID/VID annotation text without reading raw log messages."""

    normalized_keyword = normalize_sxfy_w(keyword.strip())
    if not normalized_keyword or (not event_names and not report_variables):
        return 0
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern_text = normalized_keyword if use_regex else re.escape(normalized_keyword)
    pattern = re.compile(pattern_text, flags)

    matched_ceids = {
        int(ceid)
        for ceid, name in (event_names or {}).items()
        if pattern.search(normalize_sxfy_w(f"(CEID {ceid}) {name}"))
    }
    matched_rptids = {
        int(rptid)
        for rptid, variables in (report_variables or {}).items()
        if any(
            pattern.search(normalize_sxfy_w(f"({variable.vid}) {variable.name}"))
            for variable in variables
        )
    }
    if not matched_ceids and not matched_rptids:
        return 0

    packed = bytearray((len(entries) + 7) // 8)
    for index, entry in enumerate(entries):
        if index % 8192 == 0 and cancel_check is not None and cancel_check():
            raise InterruptedError("부가정보 키워드 검색이 취소되었습니다.")
        matched = entry.ceid in matched_ceids
        if not matched and matched_rptids and entry.s6f11_rptids:
            matched = not matched_rptids.isdisjoint(entry.s6f11_rptids)
        if matched:
            packed[index >> 3] |= 1 << (index & 7)
    return int.from_bytes(packed, "little")

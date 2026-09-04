from __future__ import annotations

import threading
from datetime import datetime

import pytest
from unittest.mock import patch

from gem300_log_analyzer.analysis.keyword_index import (
    build_keyword_index,
    is_keyword_index_valid,
    keyword_index_cache_key,
    keyword_index_cache_path,
    query_keyword_mask,
)
from gem300_log_analyzer.models import LogEntry, LogType


def _entry(message: str, line_no: int) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 8, 28, 12, 0, line_no % 60),
        log_type=LogType.MMI,
        source_file="mmi.log",
        message=message,
        line_no=line_no,
    )


def _positions(mask: int) -> list[int]:
    return [position for position in range(mask.bit_length()) if mask & (1 << position)]


def test_keyword_index_returns_exact_case_insensitive_substring_matches(tmp_path) -> None:
    entries = [
        _entry("Carrier ABC load", 1),
        _entry("carrier abc mapping", 2),
        _entry("other", 3),
    ]
    index_path = build_keyword_index(entries, tmp_path / "search.sqlite")

    mask = query_keyword_mask(index_path, entries, "carrier ABC")

    assert mask is not None
    assert _positions(mask) == [0, 1]


def test_keyword_index_validates_case_and_sxfy_normalization(tmp_path) -> None:
    entries = [
        _entry("SEND S6F11W Carrier", 1),
        _entry("SEND S6F11 carrier", 2),
        _entry("SEND S6F12 Carrier", 3),
    ]
    index_path = build_keyword_index(entries, tmp_path / "search.sqlite")

    sxfy_mask = query_keyword_mask(index_path, entries, "S6F11")
    case_mask = query_keyword_mask(
        index_path,
        entries,
        "Carrier",
        case_sensitive=True,
    )

    assert sxfy_mask is not None
    assert case_mask is not None
    assert _positions(sxfy_mask) == [0, 1]
    assert _positions(case_mask) == [0, 2]


def test_short_keyword_falls_back_to_regular_scan(tmp_path) -> None:
    entries = [_entry("AB value", 1)]
    index_path = build_keyword_index(entries, tmp_path / "search.sqlite")

    assert query_keyword_mask(index_path, entries, "AB") is None


def test_keyword_index_includes_background_annotations(tmp_path) -> None:
    entry = _entry("S6F11 raw body", 1)
    entry.annotated_message = "S6F11 raw body // Carrier Arrived"
    index_path = build_keyword_index([entry], tmp_path / "search.sqlite")

    mask = query_keyword_mask(index_path, [entry], "Carrier Arrived")

    assert mask == 1


def test_keyword_index_build_honors_cancellation(tmp_path) -> None:
    entries = [_entry("target", line_no) for line_no in range(1, 20_001)]
    cancel_event = threading.Event()
    cancel_event.set()

    with pytest.raises(InterruptedError):
        build_keyword_index(
            entries,
            tmp_path / "search.sqlite",
            cancel_check=cancel_event.is_set,
        )

    assert not (tmp_path / "search.sqlite").exists()


def test_keyword_index_reuses_matching_persistent_cache(tmp_path) -> None:
    entries = [_entry("persistent target", 1)]
    cache_key = "same-analysis"
    index_path = tmp_path / "persistent.sqlite"
    build_keyword_index(entries, index_path, cache_key=cache_key)

    with patch(
        "gem300_log_analyzer.analysis.keyword_index.normalize_sxfy_w",
        side_effect=AssertionError("valid index must not be rebuilt"),
    ):
        reused = build_keyword_index(
            entries,
            index_path,
            cache_key=cache_key,
            reuse_existing=True,
        )

    assert reused == index_path
    assert is_keyword_index_valid(index_path, 1, cache_key=cache_key)
    assert not is_keyword_index_valid(index_path, 1, cache_key="changed")


def test_keyword_index_cache_key_tracks_source_file_changes(tmp_path) -> None:
    log_path = tmp_path / "MMI.log"
    log_path.write_text("first", encoding="utf-8")
    first_key = keyword_index_cache_key(
        [log_path], skip_setup_dump=True, excluded_s6f11_ceid_ranges=()
    )
    first_path = keyword_index_cache_path(tmp_path, first_key)
    log_path.write_text("second and longer", encoding="utf-8")
    second_key = keyword_index_cache_key(
        [log_path], skip_setup_dump=True, excluded_s6f11_ceid_ranges=()
    )

    assert first_key != second_key
    assert first_path != keyword_index_cache_path(tmp_path, second_key)

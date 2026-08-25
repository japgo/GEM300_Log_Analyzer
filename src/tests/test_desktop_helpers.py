from __future__ import annotations

from datetime import date, datetime, timedelta

from gem300_log_analyzer.ui.desktop_helpers import (
    aligned_line_diff,
    format_log_time,
    format_time_delta,
    format_xml_in_message,
    parse_custom_time_filter_inputs,
)


def test_format_log_time_supports_full_and_time_only_display() -> None:
    value = datetime(2026, 8, 25, 14, 7, 9, 123456)

    assert format_log_time(value, include_date=True) == "2026-08-25 14:07:09:123"
    assert format_log_time(value, include_date=False) == "14:07:09:123"


def test_format_xml_in_message_pretty_prints_non_secs_xml() -> None:
    formatted = format_xml_in_message("prefix <Root><Value>1</Value></Root> suffix")

    assert "--- XML ---" in formatted
    assert "<Value>1</Value>" in formatted
    assert formatted.endswith(" suffix")


def test_parse_custom_time_filter_inputs_rolls_time_only_end_to_next_day() -> None:
    start, end = parse_custom_time_filter_inputs(
        "23:50", "00:10", date(2026, 7, 15)
    )

    assert start == datetime(2026, 7, 15, 23, 50)
    assert end == datetime(2026, 7, 16, 0, 10)


def test_format_time_delta_keeps_existing_display_units() -> None:
    assert format_time_delta(timedelta(milliseconds=12)) == "+12ms"
    assert format_time_delta(timedelta(seconds=3, milliseconds=400)) == "+3.4s"
    assert format_time_delta(timedelta(minutes=2, seconds=10)) == "+2m 10s"


def test_aligned_line_diff_marks_replaced_lines() -> None:
    left, right, left_marks, right_marks = aligned_line_diff(
        ["same", "before"], ["same", "after"]
    )

    assert left == ["same", "before"]
    assert right == ["same", "after"]
    assert left_marks == ["", "replace"]
    assert right_marks == ["", "replace"]

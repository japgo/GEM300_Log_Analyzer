from __future__ import annotations

import threading

import pytest

from gem300_log_analyzer.db.report_variable_lookup import ReportVariable
from gem300_log_analyzer.models import LogType
from gem300_log_analyzer.parsers.log_loader import ParsingCancelled, parse_paths


def _write_mmi(path, message: str) -> None:
    path.write_text(
        f"2026-08-28 10:00:00:000|1|1|{message}\n",
        encoding="utf-8",
    )


def test_parse_paths_reuses_unchanged_file_cache(tmp_path) -> None:
    log_path = tmp_path / "MMI_2026-08-28.log"
    cache_dir = tmp_path / "cache"
    _write_mmi(log_path, "first")
    first_stats: dict[str, int] = {}
    second_stats: dict[str, int] = {}

    first_entries, _skipped, first_types = parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        cache_stats=first_stats,
    )
    second_entries, _skipped, second_types = parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        cache_stats=second_stats,
    )

    assert first_stats == {"hits": 0, "misses": 1, "files": 1}
    assert second_stats == {"hits": 1, "misses": 0, "files": 1}
    assert first_types == second_types == {log_path.name: LogType.MMI}
    assert [entry.message for entry in first_entries] == ["first"]
    assert [entry.message for entry in second_entries] == ["first"]


def test_file_change_invalidates_only_its_cache(tmp_path) -> None:
    first_path = tmp_path / "MMI_2026-08-28_A.log"
    second_path = tmp_path / "MMI_2026-08-28_B.log"
    cache_dir = tmp_path / "cache"
    _write_mmi(first_path, "first")
    _write_mmi(second_path, "second")
    parse_paths([first_path, second_path], max_workers=1, cache_dir=cache_dir)

    _write_mmi(second_path, "second changed and longer")
    stats: dict[str, int] = {}
    entries, _skipped, _types = parse_paths(
        [first_path, second_path],
        max_workers=1,
        cache_dir=cache_dir,
        cache_stats=stats,
    )

    assert stats == {"hits": 1, "misses": 1, "files": 2}
    assert [entry.message for entry in entries] == [
        "first",
        "second changed and longer",
    ]


def test_parser_option_change_invalidates_cache(tmp_path) -> None:
    log_path = tmp_path / "MMI_2026-08-28.log"
    cache_dir = tmp_path / "cache"
    _write_mmi(log_path, "normal")
    parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        skip_setup_dump=True,
    )
    stats: dict[str, int] = {}

    parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        skip_setup_dump=False,
        cache_stats=stats,
    )

    assert stats == {"hits": 0, "misses": 1, "files": 1}


def test_reference_mapping_order_does_not_invalidate_cache(tmp_path) -> None:
    log_path = tmp_path / "MMI_2026-08-28.log"
    cache_dir = tmp_path / "cache"
    _write_mmi(log_path, "normal")
    parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        event_names={2: "second", 1: "first"},
    )
    stats: dict[str, int] = {}

    parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        event_names={1: "first", 2: "second"},
        cache_stats=stats,
    )

    assert stats == {"hits": 1, "misses": 0, "files": 1}


def test_reference_mapping_change_reuses_raw_cache_and_reannotates(tmp_path) -> None:
    log_path = tmp_path / "2026-08-28 10.log"
    cache_dir = tmp_path / "cache"
    log_path.write_text(
        "10:00:00:000: [1] S6F11 W\n"
        "  <L [3]>\n"
        "    <U4 [1] 0>\n"
        "    <U4 [1] 777>\n"
        "    <L [1]>\n"
        "      <L [2]>\n"
        "        <U4 [1] 10>\n"
        "        <L [1]>\n"
        "          <A [3] ABC>\n",
        encoding="utf-8",
    )
    variables = {
        10: [
            ReportVariable(
                rptid=10,
                index_no=1,
                vid=1001,
                name="CarrierID",
            )
        ]
    }

    first_entries, _skipped, _types = parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        event_names={777: "Old Event Name"},
        report_variables=variables,
    )
    stats: dict[str, int] = {}
    second_entries, _skipped, _types = parse_paths(
        [log_path],
        max_workers=1,
        cache_dir=cache_dir,
        event_names={777: "New Event Name"},
        report_variables=variables,
        cache_stats=stats,
    )

    assert stats == {"hits": 1, "misses": 0, "files": 1}
    assert "Old Event Name" not in first_entries[0].message
    assert "Old Event Name" in first_entries[0].display_message
    assert "New Event Name" not in second_entries[0].message
    assert "New Event Name" in second_entries[0].display_message


def test_parse_paths_honors_pre_cancelled_event(tmp_path) -> None:
    log_path = tmp_path / "MMI_2026-08-28.log"
    _write_mmi(log_path, "cancel")
    cancel_event = threading.Event()
    cancel_event.set()

    with pytest.raises(ParsingCancelled):
        parse_paths([log_path], max_workers=1, cancel_event=cancel_event)


def test_progress_callback_reports_lines_inside_one_large_file(tmp_path) -> None:
    log_path = tmp_path / "MMI_2026-08-28.log"
    line_count = 20_000
    log_path.write_text(
        "".join(
            f"2026-08-28 10:00:00:000|1|{line_no}|line {line_no}\n"
            for line_no in range(1, line_count + 1)
        ),
        encoding="utf-8",
    )
    increments: list[int] = []
    detailed_updates: list[tuple[str, int, int]] = []

    parse_paths(
        [log_path],
        max_workers=1,
        progress_callback=lambda _filename, delta: increments.append(delta),
        detailed_progress_callback=lambda path, current, total: detailed_updates.append(
            (path, current, total)
        ),
    )

    assert len(increments) >= 3
    assert sum(increments) == line_count
    assert increments[0] < line_count
    assert len(detailed_updates) >= 3
    assert detailed_updates[-1] == (str(log_path), line_count, line_count)
    assert [current for _path, current, _total in detailed_updates] == sorted(
        current for _path, current, _total in detailed_updates
    )

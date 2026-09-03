from __future__ import annotations

import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
import desktop_app
from gem300_log_analyzer.analysis.alarm_summary import is_alarm_entry
from gem300_log_analyzer.analysis.gem300_trace import extract_gem300_events
from gem300_log_analyzer.analysis.reference_enrichment import (
    build_reference_match_mask,
    collect_reference_ids,
)
from gem300_log_analyzer.models import LogEntry, LogType


def _entry(
    line_no: int,
    *,
    ceid: int | None = None,
    rptids: tuple[int, ...] = (),
) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 9, 3, 10, 0),
        log_type=LogType.SECS,
        source_file="2026-09-03 10.log",
        message="",
        line_no=line_no,
        ceid=ceid,
        text_store_path="/path/that/must/not/be/read",
        message_offset=0,
        message_length=100,
        sxfy_type="S6F11",
        s6f11_rptids=rptids,
    )


def _positions(mask: int, count: int) -> list[int]:
    packed = mask.to_bytes((count + 7) // 8, "little")
    return [
        index
        for index in range(count)
        if packed[index >> 3] & (1 << (index & 7))
    ]


def test_reference_ids_are_collected_without_reading_disk_text() -> None:
    entries = [
        _entry(1, ceid=777, rptids=(10, 20)),
        _entry(2, ceid=777, rptids=(20,)),
        _entry(3, ceid=888),
    ]

    ceids, rptids = collect_reference_ids(entries)

    assert ceids == {777, 888}
    assert rptids == {10, 20}


def test_reference_name_search_uses_only_compact_metadata() -> None:
    entries = [
        _entry(1, ceid=777, rptids=(10,)),
        _entry(2, ceid=888, rptids=(20,)),
        _entry(3),
    ]
    event_names = {777: "Carrier Arrived", 888: "Process Started"}
    report_variables = {
        10: [SimpleNamespace(vid=1001, name="CarrierID")],
        20: [SimpleNamespace(vid=2001, name="ChamberPressure")],
    }

    event_mask = build_reference_match_mask(
        entries, "carrier arrived", event_names, report_variables
    )
    variable_mask = build_reference_match_mask(
        entries, "ChamberPressure", event_names, report_variables
    )

    assert _positions(event_mask, len(entries)) == [0]
    assert _positions(variable_mask, len(entries)) == [1]


def test_lazy_detail_annotation_does_not_mutate_all_entries() -> None:
    message = (
        "S6F11 W\n"
        "<L [3]>\n"
        "  <U4 [1] 0>\n"
        "  <U4 [1] 777>\n"
        "  <L [1]>\n"
        "    <L [2]>\n"
        "      <U4 [1] 10>\n"
        "      <L [1]>\n"
        "        <A [3] ABC>"
    )
    entry = LogEntry(
        timestamp=datetime(2026, 9, 3, 10, 0),
        log_type=LogType.SECS,
        source_file="SECS.log",
        message=message,
        line_no=1,
        ceid=777,
        sxfy_type="S6F11",
        s6f11_rptids=(10,),
    )
    app = SimpleNamespace(
        event_names={777: "Carrier Arrived"},
        report_variables={
            10: [SimpleNamespace(vid=1001, name="CarrierID")]
        },
        _lazy_annotation_cache=OrderedDict(),
    )

    rendered = Gem300DesktopApp._display_message_for_entry(app, entry)

    assert "Carrier Arrived" in rendered
    assert "CarrierID" in rendered
    assert entry.message_annotations == ()
    assert entry.event_name is None
    assert len(app._lazy_annotation_cache) == 1


def test_parse_hints_skip_disk_reads_for_non_candidates() -> None:
    entry = _entry(1)
    entry.log_type = LogType.MMI
    entry.scan_hints = 1

    assert not is_alarm_entry(entry)
    assert extract_gem300_events([entry]) == []


def test_desktop_reference_worker_queries_only_used_ids_and_does_not_reindex() -> None:
    entries = [_entry(1, ceid=777, rptids=(10,)), _entry(2, ceid=777)]

    class ImmediateRoot:
        @staticmethod
        def after(_delay, callback) -> None:
            callback()

    class Status:
        value = ""

        def set(self, value: str) -> None:
            self.value = value

    app = SimpleNamespace(
        _analysis_generation=3,
        root=ImmediateRoot(),
        status_var=Status(),
        event_names={},
        report_variables={},
        _annotation_revision=0,
        _lazy_annotation_cache=OrderedDict(),
        finished=0,
    )
    app._set_background_status_if_current = (
        lambda generation, text: app.status_var.set(text)
        if generation == app._analysis_generation
        else None
    )
    app._clear_keyword_match_cache = lambda: None
    app._refresh_visible_enrichment_rows = lambda refresh_detail: None
    app._refresh_stats_panel = lambda: None
    app._background_task_finished = lambda _generation: setattr(
        app, "finished", app.finished + 1
    )
    app._reference_enrichment_complete = lambda *args: (
        Gem300DesktopApp._reference_enrichment_complete(app, *args)
    )

    variables = {10: [SimpleNamespace(vid=1001, name="CarrierID")]}
    with (
        patch.object(desktop_app, "load_event_names", return_value={777: "Arrived"}) as events,
        patch.object(desktop_app, "load_report_variables", return_value=variables) as reports,
        patch.object(desktop_app, "build_keyword_index") as reindex,
    ):
        Gem300DesktopApp._reference_enrichment_worker(
            app,
            3,
            entries,
            "server",
            "database",
            "driver",
            SimpleNamespace(is_set=lambda: False),
        )

    assert events.call_args.args[0] == {777}
    assert reports.call_args.args[0] == {10}
    reindex.assert_not_called()
    assert app.event_names == {777: "Arrived"}
    assert app.report_variables == variables
    assert app.finished == 1

from __future__ import annotations

import sys
import threading
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp
from gem300_log_analyzer.models import LogEntry, LogType


class _Variable:
    def __init__(self, value=None) -> None:
        self.value = value

    def set(self, value) -> None:
        self.value = value

    def get(self):
        return self.value


class _Progress:
    def __init__(self) -> None:
        self.values = {}

    def configure(self, **kwargs) -> None:
        self.values.update(kwargs)


class _ImmediateRoot:
    @staticmethod
    def after(_delay, callback) -> None:
        callback()


class _Text:
    def __init__(self) -> None:
        self.value = ""

    def configure(self, **_kwargs) -> None:
        pass

    def delete(self, *_args) -> None:
        self.value = ""

    def insert(self, _position, value: str) -> None:
        self.value = value


class _RawCompleteShim:
    _raw_analysis_complete = Gem300DesktopApp._raw_analysis_complete

    def __init__(self) -> None:
        self._analysis_generation = 7
        self._analysis_running = True
        self._background_analysis_running = False
        self._background_task_count = 0
        self.progress = _Progress()
        self.progress_percent_var = _Variable()
        self.status_var = _Variable()
        self.calls: list[tuple[str, object]] = []

    def _clear_keyword_match_cache(self) -> None:
        self.calls.append(("clear-cache", None))

    def _update_sxfy_filters(self, entries) -> None:
        self.calls.append(("sxfy", len(entries)))

    def _set_controls_busy(self, busy: bool) -> None:
        self.calls.append(("busy", busy))

    def refresh_table(self, **kwargs) -> None:
        self.calls.append(("refresh", kwargs))

    def apply_filters(self) -> None:
        self.calls.append(("filter", None))

    def _start_background_analysis(self, *args) -> None:
        self.calls.append(("background", args[0]))


class _StatsShim:
    _stats_worker = Gem300DesktopApp._stats_worker
    _stats_complete = Gem300DesktopApp._stats_complete
    _format_top_counts = staticmethod(Gem300DesktopApp._format_top_counts)
    _entry_sxfy_type = Gem300DesktopApp._entry_sxfy_type
    _entry_key = Gem300DesktopApp._entry_key

    def __init__(self) -> None:
        self._stats_generation = 3
        self.root = _ImmediateRoot()
        self.stats_text = _Text()
        self.stats_panel_visible_var = _Variable(True)


def test_raw_entries_are_published_before_background_work_starts() -> None:
    app = _RawCompleteShim()
    entry = LogEntry(
        timestamp=datetime(2026, 8, 28, 10, 0),
        log_type=LogType.MMI,
        source_file="MMI_2026-08-28.log",
        message="raw log",
        line_no=1,
    )

    app._raw_analysis_complete(
        7,
        [entry],
        0,
        {entry.source_file: "MMI"},
        [entry.source_file],
        {"hits": 0, "files": 1},
        False,
        "server",
        "database",
        "driver",
        threading.Event(),
    )

    call_names = [name for name, _value in app.calls]
    assert app.entries == [entry]
    assert app.filtered_entries == [entry]
    assert call_names.index("refresh") < call_names.index("filter")
    assert call_names.index("filter") < call_names.index("background")
    assert dict(app.calls)["refresh"] == {"refresh_stats": False}
    assert "원본 로그 준비 완료" in app.status_var.value


def test_background_stats_are_applied_on_completion() -> None:
    app = _StatsShim()
    entries = [
        LogEntry(
            timestamp=datetime(2026, 8, 28, 10, 0),
            log_type=LogType.MMI,
            source_file="MMI.log",
            message="Alarm Code [10]",
            line_no=1,
        ),
        LogEntry(
            timestamp=datetime(2026, 8, 28, 10, 0, 1),
            log_type=LogType.SECS,
            source_file="SECS.log",
            message="S6F11 W",
            line_no=2,
            ceid=777,
            event_name="Carrier Arrived",
        ),
    ]

    app._stats_worker(3, entries, {app._entry_key(entries[0])}, threading.Event())

    assert "총 2건" in app.stats_text.value
    assert "MMI 1 / SECS 1" in app.stats_text.value
    assert "북마크 1 / Alarm 1" in app.stats_text.value
    assert "S6F11: 1" in app.stats_text.value
    assert "Carrier Arrived: 1" in app.stats_text.value

from __future__ import annotations

from gem300_log_analyzer.models import LogType
from gem300_log_analyzer.parsers.log_loader import (
    detect_log_type,
    is_supported_log_path,
    parse_paths,
)


def test_tslog_extension_is_supported_case_insensitively() -> None:
    assert is_supported_log_path("sample.tslog")
    assert is_supported_log_path("sample.TSLOG")


def test_tslog_filename_patterns_detect_log_type() -> None:
    assert detect_log_type("", "2026_07_23.tslog") == LogType.MMI
    assert detect_log_type("", "2026-07-23 10.tslog") == LogType.SECS


def test_parse_mmi_tslog_file(tmp_path) -> None:
    path = tmp_path / "2026_07_23.tslog"
    path.write_text(
        "2026-07-23 10:00:00:001|1|1|CarrierObject::StateChange\n",
        encoding="utf-8",
    )

    entries, skipped, file_types = parse_paths([path], max_workers=1)

    assert skipped == 0
    assert file_types[path.name] == LogType.MMI
    assert len(entries) == 1
    assert entries[0].source_file == path.name
    assert entries[0].message == "CarrierObject::StateChange"


def test_parse_secs_tslog_file(tmp_path) -> None:
    path = tmp_path / "2026-07-23 10.tslog"
    path.write_text(
        "10:00:00:001: [1] S1F1 W\n",
        encoding="utf-8",
    )

    entries, skipped, file_types = parse_paths([path], max_workers=1)

    assert skipped == 0
    assert file_types[path.name] == LogType.SECS
    assert len(entries) == 1
    assert entries[0].source_file == path.name
    assert entries[0].message == "S1F1 W"

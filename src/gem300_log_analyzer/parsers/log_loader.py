from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Mapping, Optional, Union

from gem300_log_analyzer.analysis.s6f11_variables import annotate_s6f11_variables
from gem300_log_analyzer.db.report_variable_lookup import ReportVariable
from gem300_log_analyzer.models import LogEntry, LogType
from gem300_log_analyzer.parsers.mmi_parser import is_mmi_content, parse_mmi_log
from gem300_log_analyzer.parsers.secs_parser import is_secs_content, parse_secs_log


FileInput = Union[str, bytes, BinaryIO]
ProgressCallback = Callable[[str, int], None]
EventNameMap = Mapping[int, str]
ReportVariableMap = Mapping[int, list[ReportVariable]]


def _timeline_sort_key(entry: LogEntry) -> tuple:
    log_type_priority = 0 if entry.log_type == LogType.MMI else 1
    return (entry.timestamp, log_type_priority, entry.source_file, entry.line_no)


def detect_log_type(text: str, filename: str = "") -> LogType:
    mmi = is_mmi_content(text, filename)
    secs = is_secs_content(text, filename)
    if mmi and not secs:
        return LogType.MMI
    if secs and not mmi:
        return LogType.SECS
    if mmi:
        return LogType.MMI
    if secs:
        return LogType.SECS
    return LogType.UNKNOWN


def read_uploaded_text(uploaded: FileInput, filename: str = "") -> str:
    if isinstance(uploaded, str):
        return uploaded
    if isinstance(uploaded, bytes):
        return uploaded.decode("utf-8", errors="replace")
    data = uploaded.read()
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def count_text_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _parse_file_text(
    filename: str,
    text: str,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]],
    event_names: Optional[EventNameMap] = None,
    report_variables: Optional[ReportVariableMap] = None,
) -> tuple[list[LogEntry], int, str, LogType]:
    log_type = detect_log_type(text, filename)

    if log_type == LogType.MMI:
        entries, skipped = parse_mmi_log(
            text,
            source_file=filename,
            skip_setup_dump=skip_setup_dump,
        )
        _apply_reference_data(entries, event_names, report_variables)
        return entries, skipped, filename, log_type

    if log_type == LogType.SECS:
        entries = parse_secs_log(
            text,
            source_file=filename,
            excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
        )
        _apply_reference_data(entries, event_names, report_variables)
        return entries, 0, filename, log_type

    entries, skipped = parse_mmi_log(
        text,
        source_file=filename,
        skip_setup_dump=skip_setup_dump,
    )
    if entries:
        _apply_reference_data(entries, event_names, report_variables)
        return entries, skipped, filename, LogType.MMI

    secs_entries = parse_secs_log(
        text,
        source_file=filename,
        excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
    )
    if secs_entries:
        _apply_reference_data(secs_entries, event_names, report_variables)
        return secs_entries, 0, filename, LogType.SECS
    return [], 0, filename, LogType.UNKNOWN


def _apply_reference_data(
    entries: list[LogEntry],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
) -> None:
    for entry in entries:
        if event_names is not None and entry.ceid is not None:
            entry.event_name = event_names.get(entry.ceid)
        if report_variables and "S6F11" in entry.message.upper():
            entry.message = annotate_s6f11_variables(entry.message, report_variables)


def parse_uploaded_files(
    files: Iterable[tuple[str, FileInput]],
    skip_setup_dump: bool = True,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]] = None,
    event_names: Optional[EventNameMap] = None,
    report_variables: Optional[ReportVariableMap] = None,
) -> tuple[list[LogEntry], int, dict[str, LogType]]:
    all_entries: list[LogEntry] = []
    total_skipped = 0
    file_types: dict[str, LogType] = {}

    for filename, content in files:
        text = read_uploaded_text(content, filename)
        entries, skipped, filename, log_type = _parse_file_text(
            filename,
            text,
            skip_setup_dump,
            excluded_s6f11_ceid_ranges,
            event_names,
            report_variables,
        )
        file_types[filename] = log_type
        total_skipped += skipped
        all_entries.extend(entries)

    all_entries.sort(key=_timeline_sort_key)
    return all_entries, total_skipped, file_types


def _parse_path(
    path: Path | str,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
) -> tuple[list[LogEntry], int, str, LogType, int]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    entries, skipped, filename, log_type = _parse_file_text(
        p.name,
        text,
        skip_setup_dump,
        excluded_s6f11_ceid_ranges,
        event_names,
        report_variables,
    )
    return entries, skipped, filename, log_type, count_text_lines(text)


def parse_paths(
    paths: Iterable[Path | str],
    skip_setup_dump: bool = True,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]] = None,
    max_workers: Optional[int] = None,
    progress_callback: Optional[ProgressCallback] = None,
    event_names: Optional[EventNameMap] = None,
    report_variables: Optional[ReportVariableMap] = None,
) -> tuple[list[LogEntry], int, dict[str, LogType]]:
    path_list = list(paths)
    if not path_list:
        return [], 0, {}

    worker_count = max_workers or len(path_list)
    worker_count = max(1, min(worker_count, len(path_list)))
    if worker_count == 1:
        results = []
        for path in path_list:
            result = _parse_path(
                path,
                skip_setup_dump,
                excluded_s6f11_ceid_ranges,
                event_names,
                report_variables,
            )
            results.append(result)
            if progress_callback is not None:
                progress_callback(result[2], result[4])
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(
                    _parse_path,
                    path,
                    skip_setup_dump,
                    excluded_s6f11_ceid_ranges,
                    event_names,
                    report_variables,
                )
                for path in path_list
            ]
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if progress_callback is not None:
                    progress_callback(result[2], result[4])

    all_entries: list[LogEntry] = []
    total_skipped = 0
    file_types: dict[str, LogType] = {}
    for entries, skipped, filename, log_type, _line_count in results:
        all_entries.extend(entries)
        total_skipped += skipped
        file_types[filename] = log_type

    all_entries.sort(key=_timeline_sort_key)
    return all_entries, total_skipped, file_types

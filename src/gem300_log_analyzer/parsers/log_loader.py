from __future__ import annotations

import hashlib
import multiprocessing
import os
import pickle
import re
import uuid
from concurrent.futures import (
    FIRST_COMPLETED,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Mapping, Optional, Union

from gem300_log_analyzer.analysis.alarm_summary import is_alarm_message
from gem300_log_analyzer.analysis.gem300_trace import is_gem300_event_message
from gem300_log_analyzer.analysis.s6f11_variables import build_s6f11_annotations
from gem300_log_analyzer.db.report_variable_lookup import ReportVariable
from gem300_log_analyzer.models import (
    SCAN_HINT_ALARM,
    SCAN_HINT_GEM300_EVENT,
    SCAN_HINTS_READY,
    LogEntry,
    LogType,
)
from gem300_log_analyzer.parsers.mmi_parser import is_mmi_content, parse_mmi_log
from gem300_log_analyzer.parsers.secs_parser import is_secs_content, parse_secs_log
from gem300_log_analyzer.storage.disk_text_store import (
    DiskTextWriter,
    close_disk_text_store,
)


FileInput = Union[str, bytes, BinaryIO]
ProgressCallback = Callable[[str, int], None]
DetailedProgressCallback = Callable[[str, int, int], None]
EventNameMap = Mapping[int, str]
ReportVariableMap = Mapping[int, list[ReportVariable]]
SUPPORTED_LOG_SUFFIXES = frozenset({".log", ".txt", ".tslog"})
ANALYSIS_CACHE_SCHEMA = 4
PARALLEL_PARSE_MIN_BYTES = 64 * 1024 * 1024
MAX_INTRA_FILE_WORKERS = 4
SXFy_RE = re.compile(r"\bS(?P<stream>\d+)F(?P<function>\d+)W?\b", re.I)
MMI_HEADER_BYTES_RE = re.compile(
    rb"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3}\|\d+\|\d+\|"
)
SECS_HEADER_BYTES_RE = re.compile(
    rb"^\d{2}:\d{2}:\d{2}:\d{3}:\s+\[\d+\]"
)


@dataclass(frozen=True, slots=True)
class _FileSegment:
    start_offset: int
    end_offset: int
    start_line_no: int
    end_line_no: int


class ParsingCancelled(Exception):
    """Raised when a caller requests cancellation during file parsing."""


def _is_cancelled(cancel_event) -> bool:
    return cancel_event is not None and cancel_event.is_set()


def _raise_if_cancelled(cancel_event) -> None:
    if _is_cancelled(cancel_event):
        raise ParsingCancelled("로그 분석이 취소되었습니다.")


def is_supported_log_path(path: Path | str) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_LOG_SUFFIXES


def _timeline_sort_key(entry: LogEntry) -> tuple:
    log_type_priority = 0 if entry.log_type == LogType.MMI else 1
    return (entry.timestamp, log_type_priority, entry.source_file, entry.line_no)


def _assign_timeline_indices(entries: list[LogEntry]) -> None:
    for index, entry in enumerate(entries):
        entry.timeline_index = index


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
    cancel_check: Callable[[], bool] | None = None,
    line_progress_callback: Callable[[int], None] | None = None,
) -> tuple[list[LogEntry], int, str, LogType]:
    log_type = detect_log_type(text, filename)

    if log_type == LogType.MMI:
        entries, skipped = parse_mmi_log(
            text,
            source_file=filename,
            skip_setup_dump=skip_setup_dump,
            cancel_check=cancel_check,
            progress_callback=line_progress_callback,
        )
        return entries, skipped, filename, log_type

    if log_type == LogType.SECS:
        entries = parse_secs_log(
            text,
            source_file=filename,
            excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
            cancel_check=cancel_check,
            progress_callback=line_progress_callback,
        )
        return entries, 0, filename, log_type

    entries, skipped = parse_mmi_log(
        text,
        source_file=filename,
        skip_setup_dump=skip_setup_dump,
        cancel_check=cancel_check,
        progress_callback=line_progress_callback,
    )
    if entries:
        return entries, skipped, filename, LogType.MMI

    secs_entries = parse_secs_log(
        text,
        source_file=filename,
        excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
        cancel_check=cancel_check,
        progress_callback=line_progress_callback,
    )
    if secs_entries:
        return secs_entries, 0, filename, LogType.SECS
    return [], 0, filename, LogType.UNKNOWN


def apply_reference_data(
    entries: list[LogEntry],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
    *,
    cancel_check: Callable[[], bool] | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    total = len(entries)
    if cancel_check is not None and cancel_check():
        raise ParsingCancelled("부가정보 처리가 취소되었습니다.")
    last_reported = 0
    for index, entry in enumerate(entries, start=1):
        if index % 4096 == 0 and cancel_check is not None and cancel_check():
            raise ParsingCancelled("부가정보 처리가 취소되었습니다.")
        if event_names is not None and entry.ceid is not None:
            entry.event_name = event_names.get(entry.ceid)
        is_s6f11 = entry.sxfy_type == "S6F11"
        if entry.sxfy_type is None:
            is_s6f11 = "S6F11" in entry.message.upper()
        if is_s6f11 and (report_variables or event_names):
            message = entry.message
            entry.message_annotations = build_s6f11_annotations(
                message, report_variables, event_names
            )
        else:
            entry.message_annotations = ()
        entry.annotated_message = None
        if index % 4096 == 0 and progress_callback is not None:
            progress_callback(index, total)
            last_reported = index
    if progress_callback is not None and last_reported != total:
        progress_callback(total, total)


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
        if event_names or report_variables:
            apply_reference_data(entries, event_names, report_variables)
        file_types[filename] = log_type
        total_skipped += skipped
        all_entries.extend(entries)

    all_entries.sort(key=_timeline_sort_key)
    _assign_timeline_indices(all_entries)
    return all_entries, total_skipped, file_types


def _parse_path(
    path: Path | str,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
    progress_callback: Optional[ProgressCallback],
    detailed_progress_callback: Optional[DetailedProgressCallback],
    cache_dir: Path | None,
    cache_signature: str,
    cancel_event,
    intra_file_workers: int = 1,
) -> tuple[list[LogEntry], int, str, LogType, int, bool]:
    p = Path(path)
    _raise_if_cancelled(cancel_event)
    fingerprint = _path_fingerprint(p)
    cache_path = _analysis_cache_path(cache_dir, p) if cache_dir else None
    cached = _load_analysis_cache(cache_path, fingerprint, cache_signature)
    if cached is not None:
        entries, skipped, filename, log_type, line_count = cached
        _raise_if_cancelled(cancel_event)
        if event_names or report_variables:
            apply_reference_data(
                entries,
                event_names,
                report_variables,
                cancel_check=lambda: _is_cancelled(cancel_event),
            )
        if progress_callback is not None:
            progress_callback(filename, line_count)
        if detailed_progress_callback is not None:
            detailed_progress_callback(str(p), line_count, line_count)
        return entries, skipped, filename, log_type, line_count, True

    if cache_path is not None:
        return _parse_path_disk_backed(
            p,
            fingerprint,
            cache_path,
            cache_signature,
            skip_setup_dump,
            excluded_s6f11_ceid_ranges,
            event_names,
            report_variables,
            progress_callback,
            detailed_progress_callback,
            cancel_event,
            intra_file_workers,
        )

    text = _read_path_text(p, cancel_event)
    line_count = count_text_lines(text)
    reported_lines = 0

    def report_line_position(line_no: int) -> None:
        nonlocal reported_lines
        completed = min(line_count, max(reported_lines, line_no))
        delta = completed - reported_lines
        if delta > 0 and progress_callback is not None:
            progress_callback(p.name, delta)
        if delta > 0 and detailed_progress_callback is not None:
            detailed_progress_callback(str(p), completed, line_count)
        reported_lines = completed

    entries, skipped, filename, log_type = _parse_file_text(
        p.name,
        text,
        skip_setup_dump,
        excluded_s6f11_ceid_ranges,
        event_names,
        report_variables,
        cancel_check=lambda: _is_cancelled(cancel_event),
        line_progress_callback=report_line_position,
    )
    report_line_position(line_count)
    _raise_if_cancelled(cancel_event)
    _save_analysis_cache(
        cache_path,
        fingerprint,
        cache_signature,
        entries,
        skipped,
        filename,
        log_type,
        line_count,
    )
    if event_names or report_variables:
        apply_reference_data(
            entries,
            event_names,
            report_variables,
            cancel_check=lambda: _is_cancelled(cancel_event),
        )
    return entries, skipped, filename, log_type, line_count, False


def _offload_entry(entry: LogEntry, writer: DiskTextWriter) -> None:
    message = entry.message
    raw_line = entry.raw_line
    sxfy_match = SXFy_RE.search(message)
    if sxfy_match:
        entry.sxfy_type = (
            f"S{sxfy_match.group('stream')}F{sxfy_match.group('function')}"
        ).upper()
    entry.scan_hints = SCAN_HINTS_READY
    if is_alarm_message(message, entry.color_index, entry.level_name):
        entry.scan_hints |= SCAN_HINT_ALARM
    if entry.log_type == LogType.MMI and is_gem300_event_message(message):
        entry.scan_hints |= SCAN_HINT_GEM300_EVENT
    message_ref = writer.append(message)
    raw_line_ref = message_ref if raw_line == message else writer.append(raw_line)
    entry.text_store_path = message_ref.path
    entry.message_offset = message_ref.offset
    entry.message_length = message_ref.length
    entry.raw_line_offset = raw_line_ref.offset
    entry.raw_line_length = raw_line_ref.length
    entry.message = ""
    entry.raw_line = ""
    entry.secs_message = None


def _iter_text_range(
    path: Path | str,
    start_offset: int,
    end_offset: int,
):
    with Path(path).open("rb") as handle:
        handle.seek(start_offset)
        while handle.tell() < end_offset:
            raw_line = handle.readline()
            if not raw_line:
                break
            yield raw_line.decode("utf-8", errors="replace")


def _scan_file_segments(
    path: Path,
    log_type: LogType,
    worker_count: int,
    cancel_event,
) -> tuple[list[_FileSegment], int, bool]:
    """Find safe entry-aligned byte ranges without retaining the file in memory."""
    file_size = path.stat().st_size
    if file_size <= 0 or worker_count <= 1:
        return [], _count_path_lines(path, cancel_event), False
    header_pattern = (
        MMI_HEADER_BYTES_RE if log_type == LogType.MMI else SECS_HEADER_BYTES_RE
    )
    targets = [file_size * index // worker_count for index in range(1, worker_count)]
    boundaries: list[tuple[int, int]] = [(0, 1)]
    newline_count = 0
    position = 0
    last_byte = b""
    marker_tail = b""
    has_setup_markers = False

    def inspect(data: bytes) -> None:
        nonlocal marker_tail, has_setup_markers, last_byte
        if not data:
            return
        last_byte = data[-1:]
        if log_type == LogType.MMI and not has_setup_markers:
            sample = (marker_tail + data).upper()
            if b"] LOGGING" in sample or b"] FINISH" in sample:
                has_setup_markers = True
            marker_tail = sample[-64:]

    with path.open("rb") as handle:
        for target in targets:
            while position < target:
                _raise_if_cancelled(cancel_event)
                data = handle.read(min(8 * 1024 * 1024, target - position))
                if not data:
                    break
                newline_count += data.count(b"\n")
                position += len(data)
                inspect(data)
            if position >= file_size:
                break
            if position > 0 and last_byte != b"\n":
                data = handle.readline()
                newline_count += data.count(b"\n")
                position += len(data)
                inspect(data)
            while position < file_size:
                _raise_if_cancelled(cancel_event)
                line_start = position
                line_no = newline_count + 1
                data = handle.readline()
                if not data:
                    position = file_size
                    break
                newline_count += data.count(b"\n")
                position += len(data)
                inspect(data)
                if header_pattern.match(data):
                    boundaries.append((line_start, line_no))
                    break
        while position < file_size:
            _raise_if_cancelled(cancel_event)
            data = handle.read(8 * 1024 * 1024)
            if not data:
                break
            newline_count += data.count(b"\n")
            position += len(data)
            inspect(data)

    line_count = newline_count + int(bool(last_byte and last_byte != b"\n"))
    boundaries.append((file_size, line_count + 1))
    unique_boundaries: list[tuple[int, int]] = []
    for boundary in boundaries:
        if unique_boundaries and unique_boundaries[-1][0] == boundary[0]:
            continue
        unique_boundaries.append(boundary)
    segments = [
        _FileSegment(start, end, start_line, end_line)
        for (start, start_line), (end, end_line) in zip(
            unique_boundaries, unique_boundaries[1:]
        )
        if end > start
    ]
    return segments, line_count, has_setup_markers


def _parse_segment_worker(
    path_text: str,
    log_type_value: str,
    segment: _FileSegment,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: tuple[tuple[int, int], ...],
    text_path_text: str,
    result_path_text: str,
    cancel_marker_text: str,
    progress_path_text: str,
) -> tuple[str, int]:
    """Parse one safe file range in a spawned process and publish compact files."""
    path = Path(path_text)
    log_type = LogType(log_type_value)
    writer = DiskTextWriter(text_path_text)
    cancel_marker = Path(cancel_marker_text)
    progress_path = Path(progress_path_text)
    last_progress = 0

    def report_progress(line_no: int) -> None:
        nonlocal last_progress
        completed = min(
            segment.end_line_no - segment.start_line_no,
            max(0, line_no - segment.start_line_no + 1),
        )
        if completed - last_progress >= 65_536:
            progress_path.write_text(str(completed), encoding="ascii")
            last_progress = completed

    try:
        lines = _iter_text_range(path, segment.start_offset, segment.end_offset)
        callback = lambda entry: _offload_entry(entry, writer)
        cancel_check = cancel_marker.exists
        if log_type == LogType.MMI:
            entries, skipped = parse_mmi_log(
                lines,
                source_file=path.name,
                skip_setup_dump=skip_setup_dump,
                cancel_check=cancel_check,
                progress_callback=report_progress,
                entry_callback=callback,
                line_no_offset=segment.start_line_no - 1,
            )
        else:
            entries = parse_secs_log(
                lines,
                source_file=path.name,
                excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
                cancel_check=cancel_check,
                progress_callback=report_progress,
                entry_callback=callback,
                line_no_offset=segment.start_line_no - 1,
            )
            skipped = 0
        if cancel_check():
            raise InterruptedError("로그 분석이 취소되었습니다.")
        writer.commit()
        result_path = Path(result_path_text)
        temporary = result_path.with_suffix(".tmp")
        with temporary.open("wb") as handle:
            pickle.dump((entries, skipped), handle, protocol=pickle.HIGHEST_PROTOCOL)
        temporary.replace(result_path)
        return result_path_text, segment.end_line_no - segment.start_line_no
    except Exception:
        writer.abort()
        raise


def _parse_path_disk_backed(
    path: Path,
    fingerprint: tuple[str, int, int],
    cache_path: Path,
    cache_signature: str,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
    progress_callback: Optional[ProgressCallback],
    detailed_progress_callback: Optional[DetailedProgressCallback],
    cancel_event,
    intra_file_workers: int = 1,
) -> tuple[list[LogEntry], int, str, LogType, int, bool]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        sample = handle.read(8000)
    detected_log_type = detect_log_type(sample, path.name)
    requested_workers = max(
        1, min(int(intra_file_workers), MAX_INTRA_FILE_WORKERS)
    )
    should_try_parallel = (
        requested_workers > 1
        and path.stat().st_size >= PARALLEL_PARSE_MIN_BYTES
        and detected_log_type in (LogType.MMI, LogType.SECS)
    )
    if should_try_parallel:
        segments, line_count, has_setup_markers = _scan_file_segments(
            path, detected_log_type, requested_workers, cancel_event
        )
        if len(segments) > 1 and not (
            detected_log_type == LogType.MMI and has_setup_markers
        ):
            try:
                return _parse_path_disk_backed_parallel(
                    path,
                    fingerprint,
                    cache_path,
                    cache_signature,
                    detected_log_type,
                    segments,
                    line_count,
                    skip_setup_dump,
                    excluded_s6f11_ceid_ranges,
                    event_names,
                    report_variables,
                    progress_callback,
                    detailed_progress_callback,
                    cancel_event,
                )
            except (BrokenProcessPool, RuntimeError):
                _raise_if_cancelled(cancel_event)
    else:
        line_count = _count_path_lines(path, cancel_event)
    reported_lines = 0

    def report_line_position(line_no: int) -> None:
        nonlocal reported_lines
        completed = min(line_count, max(reported_lines, line_no))
        delta = completed - reported_lines
        if delta > 0 and progress_callback is not None:
            progress_callback(path.name, delta)
        if delta > 0 and detailed_progress_callback is not None:
            detailed_progress_callback(str(path), completed, line_count)
        reported_lines = completed

    text_path = _analysis_text_path(cache_path, fingerprint, cache_signature)
    writer = DiskTextWriter(text_path)

    def offload_entry(entry: LogEntry) -> None:
        _offload_entry(entry, writer)

    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            sample = handle.read(8000)
            handle.seek(0)
            log_type = detected_log_type
            if log_type == LogType.MMI:
                entries, skipped = parse_mmi_log(
                    handle,
                    source_file=path.name,
                    skip_setup_dump=skip_setup_dump,
                    cancel_check=lambda: _is_cancelled(cancel_event),
                    progress_callback=report_line_position,
                    entry_callback=offload_entry,
                )
            elif log_type == LogType.SECS:
                entries = parse_secs_log(
                    handle,
                    source_file=path.name,
                    excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
                    cancel_check=lambda: _is_cancelled(cancel_event),
                    progress_callback=report_line_position,
                    entry_callback=offload_entry,
                )
                skipped = 0
            else:
                entries, skipped = parse_mmi_log(
                    handle,
                    source_file=path.name,
                    skip_setup_dump=skip_setup_dump,
                    cancel_check=lambda: _is_cancelled(cancel_event),
                    progress_callback=report_line_position,
                    entry_callback=offload_entry,
                )
                if entries:
                    log_type = LogType.MMI
                else:
                    handle.seek(0)
                    reported_lines = 0
                    entries = parse_secs_log(
                        handle,
                        source_file=path.name,
                        excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
                        cancel_check=lambda: _is_cancelled(cancel_event),
                        progress_callback=report_line_position,
                        entry_callback=offload_entry,
                    )
                    skipped = 0
                    log_type = LogType.SECS if entries else LogType.UNKNOWN
        report_line_position(line_count)
        _raise_if_cancelled(cancel_event)
        writer.commit()
    except Exception:
        writer.abort()
        raise

    _save_analysis_cache(
        cache_path,
        fingerprint,
        cache_signature,
        entries,
        skipped,
        path.name,
        log_type,
        line_count,
    )
    if event_names or report_variables:
        apply_reference_data(
            entries,
            event_names,
            report_variables,
            cancel_check=lambda: _is_cancelled(cancel_event),
        )
    return entries, skipped, path.name, log_type, line_count, False


def _parse_path_disk_backed_parallel(
    path: Path,
    fingerprint: tuple[str, int, int],
    cache_path: Path,
    cache_signature: str,
    log_type: LogType,
    segments: list[_FileSegment],
    line_count: int,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
    progress_callback: Optional[ProgressCallback],
    detailed_progress_callback: Optional[DetailedProgressCallback],
    cancel_event,
) -> tuple[list[LogEntry], int, str, LogType, int, bool]:
    base_text_path = _analysis_text_path(cache_path, fingerprint, cache_signature)
    run_key = uuid.uuid4().hex
    cancel_marker = cache_path.with_name(f"{cache_path.stem}-{run_key}.cancel")
    result_paths: list[Path] = []
    text_paths: list[Path] = []
    progress_paths: list[Path] = []
    futures = {}
    completed_lines = 0
    excluded_ranges = tuple(excluded_s6f11_ceid_ranges or ())
    try:
        context = multiprocessing.get_context("spawn")
        executor = ProcessPoolExecutor(
            max_workers=len(segments), mp_context=context
        )
        try:
            for index, segment in enumerate(segments):
                text_path = base_text_path.with_name(
                    f"{base_text_path.stem}-part{index + 1}.texts"
                )
                result_path = cache_path.with_name(
                    f"{cache_path.stem}-{run_key}-part{index + 1}.pickle"
                )
                text_paths.append(text_path)
                result_paths.append(result_path)
                progress_path = cache_path.with_name(
                    f"{cache_path.stem}-{run_key}-part{index + 1}.progress"
                )
                progress_paths.append(progress_path)
                future = executor.submit(
                    _parse_segment_worker,
                    str(path),
                    log_type.value,
                    segment,
                    skip_setup_dump,
                    excluded_ranges,
                    str(text_path),
                    str(result_path),
                    str(cancel_marker),
                    str(progress_path),
                )
                futures[future] = (segment, progress_path)
            pending = set(futures)
            progress_by_future = {future: 0 for future in futures}

            def report_combined_progress() -> None:
                nonlocal completed_lines
                for active_future, (active_segment, progress_path) in futures.items():
                    if active_future.done():
                        progress_by_future[active_future] = (
                            active_segment.end_line_no - active_segment.start_line_no
                        )
                        continue
                    try:
                        progress_by_future[active_future] = max(
                            progress_by_future[active_future],
                            int(progress_path.read_text(encoding="ascii") or 0),
                        )
                    except (OSError, ValueError):
                        continue
                current_lines = min(line_count, sum(progress_by_future.values()))
                delta = current_lines - completed_lines
                if delta <= 0:
                    return
                if progress_callback is not None:
                    progress_callback(path.name, delta)
                if detailed_progress_callback is not None:
                    detailed_progress_callback(str(path), current_lines, line_count)
                completed_lines = current_lines

            while pending:
                if _is_cancelled(cancel_event):
                    cancel_marker.touch(exist_ok=True)
                    for future in pending:
                        future.cancel()
                    raise ParsingCancelled("로그 분석이 취소되었습니다.")
                done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                report_combined_progress()
                for future in done:
                    future.result()
                report_combined_progress()
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

        entries: list[LogEntry] = []
        skipped = 0
        for result_path in result_paths:
            with result_path.open("rb") as handle:
                segment_entries, segment_skipped = pickle.load(handle)
            entries.extend(segment_entries)
            skipped += int(segment_skipped)
        entries.sort(key=lambda entry: entry.line_no)
        if completed_lines < line_count:
            delta = line_count - completed_lines
            if progress_callback is not None:
                progress_callback(path.name, delta)
            if detailed_progress_callback is not None:
                detailed_progress_callback(str(path), line_count, line_count)
        _raise_if_cancelled(cancel_event)
        _save_analysis_cache(
            cache_path,
            fingerprint,
            cache_signature,
            entries,
            skipped,
            path.name,
            log_type,
            line_count,
        )
        if event_names or report_variables:
            apply_reference_data(
                entries,
                event_names,
                report_variables,
                cancel_check=lambda: _is_cancelled(cancel_event),
            )
        return entries, skipped, path.name, log_type, line_count, False
    except BaseException:
        for text_path in text_paths:
            try:
                close_disk_text_store(text_path)
                text_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    finally:
        cancel_marker.unlink(missing_ok=True)
        for result_path in result_paths:
            result_path.unlink(missing_ok=True)
            result_path.with_suffix(".tmp").unlink(missing_ok=True)
        for progress_path in progress_paths:
            progress_path.unlink(missing_ok=True)


def _count_path_lines(path: Path, cancel_event) -> int:
    line_count = 0
    last_byte = b""
    with path.open("rb") as handle:
        while True:
            _raise_if_cancelled(cancel_event)
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            line_count += chunk.count(b"\n")
            last_byte = chunk[-1:]
    if last_byte and last_byte != b"\n":
        line_count += 1
    return line_count


def _read_path_text(path: Path, cancel_event) -> str:
    chunks: list[bytes] = []
    with path.open("rb") as handle:
        while True:
            _raise_if_cancelled(cancel_event)
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _path_fingerprint(path: Path) -> tuple[str, int, int]:
    stat = path.stat()
    return str(path.resolve()), stat.st_size, stat.st_mtime_ns


def _analysis_cache_path(cache_dir: Path, path: Path) -> Path:
    path_key = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()
    return cache_dir / f"{path_key}.pickle"


def _analysis_text_path(
    cache_path: Path,
    fingerprint: tuple[str, int, int],
    cache_signature: str,
) -> Path:
    fingerprint_key = hashlib.sha256(
        pickle.dumps((fingerprint, cache_signature), protocol=5)
    ).hexdigest()[:16]
    return cache_path.with_name(f"{cache_path.stem}-{fingerprint_key}.texts")


def cleanup_stale_disk_text_stores(
    paths: Iterable[Path | str],
    entries: Iterable[LogEntry],
    cache_dir: Path | str,
) -> None:
    """Remove superseded sidecars for the files in the completed analysis."""

    cache_root = Path(cache_dir)
    active_paths = {
        entry.text_store_path
        for entry in entries
        if entry.text_store_path is not None
    }
    for path in paths:
        cache_path = _analysis_cache_path(cache_root, Path(path))
        for candidate in cache_root.glob(f"{cache_path.stem}-*.texts"):
            if str(candidate) in active_paths:
                continue
            try:
                close_disk_text_store(candidate)
                candidate.unlink(missing_ok=True)
            except OSError:
                continue


def _analysis_options_signature(
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]],
    event_names: Optional[EventNameMap],
    report_variables: Optional[ReportVariableMap],
) -> str:
    excluded_ranges = tuple(
        sorted((int(start), int(end)) for start, end in (excluded_s6f11_ceid_ranges or ()))
    )
    payload = (
        ANALYSIS_CACHE_SCHEMA,
        bool(skip_setup_dump),
        excluded_ranges,
    )
    return hashlib.sha256(pickle.dumps(payload, protocol=5)).hexdigest()


def _load_analysis_cache(
    cache_path: Path | None,
    fingerprint: tuple[str, int, int],
    signature: str,
):
    if cache_path is None or not cache_path.is_file():
        return None
    try:
        with cache_path.open("rb") as handle:
            payload = pickle.load(handle)
        if payload.get("schema") != ANALYSIS_CACHE_SCHEMA:
            return None
        if tuple(payload.get("fingerprint", ())) != fingerprint:
            return None
        if payload.get("signature") != signature:
            return None
        entries = payload["entries"]
        if not _disk_text_references_available(entries):
            return None
        log_type = LogType(payload["log_type"])
        return (
            entries,
            int(payload["skipped"]),
            str(payload["filename"]),
            log_type,
            int(payload["line_count"]),
        )
    except (OSError, EOFError, pickle.PickleError, AttributeError, KeyError, ValueError):
        return None


def _disk_text_references_available(entries: list[LogEntry]) -> bool:
    required_sizes: dict[str, int] = {}
    for entry in entries:
        if entry.text_store_path is None:
            continue
        required_sizes[entry.text_store_path] = max(
            required_sizes.get(entry.text_store_path, 0),
            entry.message_offset + entry.message_length,
            entry.raw_line_offset + entry.raw_line_length,
        )
    for path_text, minimum_size in required_sizes.items():
        try:
            if Path(path_text).stat().st_size < minimum_size:
                return False
        except OSError:
            return False
    return True


def _save_analysis_cache(
    cache_path: Path | None,
    fingerprint: tuple[str, int, int],
    signature: str,
    entries: list[LogEntry],
    skipped: int,
    filename: str,
    log_type: LogType,
    line_count: int,
) -> None:
    if cache_path is None:
        return
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = cache_path.with_suffix(".tmp")
        payload = {
            "schema": ANALYSIS_CACHE_SCHEMA,
            "fingerprint": fingerprint,
            "signature": signature,
            "entries": entries,
            "skipped": skipped,
            "filename": filename,
            "log_type": log_type.value,
            "line_count": line_count,
        }
        with temporary_path.open("wb") as handle:
            pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
        temporary_path.replace(cache_path)
    except OSError:
        return


def parse_paths(
    paths: Iterable[Path | str],
    skip_setup_dump: bool = True,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]] = None,
    max_workers: Optional[int] = None,
    progress_callback: Optional[ProgressCallback] = None,
    detailed_progress_callback: Optional[DetailedProgressCallback] = None,
    event_names: Optional[EventNameMap] = None,
    report_variables: Optional[ReportVariableMap] = None,
    cache_dir: Path | str | None = None,
    cache_stats: dict[str, int] | None = None,
    cancel_event=None,
) -> tuple[list[LogEntry], int, dict[str, LogType]]:
    path_list = list(paths)
    if not path_list:
        return [], 0, {}

    default_workers = min(os.cpu_count() or 1, 8)
    requested_worker_count = max_workers or default_workers
    requested_worker_count = max(1, min(requested_worker_count, 8))
    file_worker_count = max(1, min(requested_worker_count, len(path_list), 8))
    intra_file_workers = requested_worker_count if len(path_list) == 1 else 1
    resolved_cache_dir = Path(cache_dir) if cache_dir is not None else None
    cache_signature = _analysis_options_signature(
        skip_setup_dump,
        excluded_s6f11_ceid_ranges,
        event_names,
        report_variables,
    )
    _raise_if_cancelled(cancel_event)
    if file_worker_count == 1:
        results = []
        for path in path_list:
            result = _parse_path(
                path,
                skip_setup_dump,
                excluded_s6f11_ceid_ranges,
                event_names,
                report_variables,
                progress_callback,
                detailed_progress_callback,
                resolved_cache_dir,
                cache_signature,
                cancel_event,
                intra_file_workers,
            )
            results.append(result)
    else:
        with ThreadPoolExecutor(max_workers=file_worker_count) as executor:
            futures = {
                executor.submit(
                    _parse_path,
                    path,
                    skip_setup_dump,
                    excluded_s6f11_ceid_ranges,
                    event_names,
                    report_variables,
                    progress_callback,
                    detailed_progress_callback,
                    resolved_cache_dir,
                    cache_signature,
                    cancel_event,
                    1,
                ): index
                for index, path in enumerate(path_list)
            }
            indexed_results = []
            for future in as_completed(futures):
                _raise_if_cancelled(cancel_event)
                result = future.result()
                indexed_results.append((futures[future], result))
            indexed_results.sort(key=lambda item: item[0])
            results = [result for _index, result in indexed_results]

    all_entries: list[LogEntry] = []
    total_skipped = 0
    file_types: dict[str, LogType] = {}
    cache_hits = 0
    for entries, skipped, filename, log_type, _line_count, cache_hit in results:
        all_entries.extend(entries)
        total_skipped += skipped
        file_types[filename] = log_type
        cache_hits += int(cache_hit)

    _raise_if_cancelled(cancel_event)
    all_entries.sort(key=_timeline_sort_key)
    _assign_timeline_indices(all_entries)
    if cache_stats is not None:
        cache_stats.clear()
        cache_stats.update(
            hits=cache_hits,
            misses=len(results) - cache_hits,
            files=len(results),
        )
    return all_entries, total_skipped, file_types

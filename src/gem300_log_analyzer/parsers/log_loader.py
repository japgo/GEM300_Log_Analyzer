from __future__ import annotations

import re
from pathlib import Path
from typing import BinaryIO, Iterable, Optional, Union

from gem300_log_analyzer.models import LogEntry, LogType
from gem300_log_analyzer.parsers.mmi_parser import is_mmi_content, parse_mmi_log
from gem300_log_analyzer.parsers.secs_parser import is_secs_content, parse_secs_log


FileInput = Union[str, bytes, BinaryIO]


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


def parse_uploaded_files(
    files: Iterable[tuple[str, FileInput]],
    skip_setup_dump: bool = True,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]] = None,
) -> tuple[list[LogEntry], int, dict[str, LogType]]:
    all_entries: list[LogEntry] = []
    total_skipped = 0
    file_types: dict[str, LogType] = {}

    for filename, content in files:
        text = read_uploaded_text(content, filename)
        log_type = detect_log_type(text, filename)
        file_types[filename] = log_type

        if log_type == LogType.MMI:
            entries, skipped = parse_mmi_log(
                text,
                source_file=filename,
                skip_setup_dump=skip_setup_dump,
            )
            total_skipped += skipped
            all_entries.extend(entries)
        elif log_type == LogType.SECS:
            all_entries.extend(
                parse_secs_log(
                    text,
                    source_file=filename,
                    excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
                )
            )
        else:
            entries, skipped = parse_mmi_log(
                text,
                source_file=filename,
                skip_setup_dump=skip_setup_dump,
            )
            if entries:
                total_skipped += skipped
                all_entries.extend(entries)
                file_types[filename] = LogType.MMI
            else:
                secs_entries = parse_secs_log(
                    text,
                    source_file=filename,
                    excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
                )
                if secs_entries:
                    all_entries.extend(secs_entries)
                    file_types[filename] = LogType.SECS

    all_entries.sort(key=lambda e: (e.timestamp, e.source_file, e.line_no))
    return all_entries, total_skipped, file_types


def parse_paths(
    paths: Iterable[Path | str],
    skip_setup_dump: bool = True,
    excluded_s6f11_ceid_ranges: Optional[Iterable[tuple[int, int]]] = None,
) -> tuple[list[LogEntry], int, dict[str, LogType]]:
    files: list[tuple[str, str]] = []
    for path in paths:
        p = Path(path)
        files.append((p.name, p.read_text(encoding="utf-8", errors="replace")))
    return parse_uploaded_files(
        files,
        skip_setup_dump=skip_setup_dump,
        excluded_s6f11_ceid_ranges=excluded_s6f11_ceid_ranges,
    )

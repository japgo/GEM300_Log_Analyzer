from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Callable, Iterable

from gem300_log_analyzer.analysis.keyword_search import normalize_sxfy_w
from gem300_log_analyzer.models import LogEntry


INDEX_SCHEMA_VERSION = 1
INDEX_BATCH_SIZE = 10_000


def build_keyword_index(
    entries: Iterable[LogEntry],
    index_path: Path | str,
    *,
    cancel_check: Callable[[], bool] | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> Path:
    """Build an atomic disk-backed trigram index for the current timeline."""
    entry_list = entries if isinstance(entries, list) else list(entries)
    destination = Path(index_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".building.sqlite")
    temporary.unlink(missing_ok=True)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(temporary)
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute(
            "CREATE VIRTUAL TABLE log_search USING fts5("
            "message, tokenize='trigram')"
        )
        connection.execute(
            "CREATE TABLE index_metadata (schema_version INTEGER, entry_count INTEGER)"
        )
        total = len(entry_list)
        for start in range(0, total, INDEX_BATCH_SIZE):
            if cancel_check is not None and cancel_check():
                raise InterruptedError("검색 인덱스 생성이 취소되었습니다.")
            batch = entry_list[start : start + INDEX_BATCH_SIZE]
            connection.executemany(
                "INSERT INTO log_search(rowid, message) VALUES (?, ?)",
                (
                    (start + offset + 1, normalize_sxfy_w(entry.display_message))
                    for offset, entry in enumerate(batch)
                ),
            )
            completed = start + len(batch)
            if progress_callback is not None:
                progress_callback(completed, total)
        connection.execute(
            "INSERT INTO index_metadata(schema_version, entry_count) VALUES (?, ?)",
            (INDEX_SCHEMA_VERSION, total),
        )
        connection.commit()
        connection.close()
        connection = None
        temporary.replace(destination)
        return destination
    except Exception:
        if connection is not None:
            connection.close()
        temporary.unlink(missing_ok=True)
        raise


def query_keyword_mask(
    index_path: Path | str | None,
    entries: list[LogEntry],
    keyword: str,
    *,
    case_sensitive: bool = False,
    cancel_check: Callable[[], bool] | None = None,
) -> int | None:
    """Return a compact match bitmask, or None when the index cannot be used."""
    normalized_keyword = normalize_sxfy_w(keyword.strip())
    if index_path is None or len(normalized_keyword) < 3:
        return None
    path = Path(index_path)
    if not path.is_file():
        return None
    query = f'"{normalized_keyword.replace(chr(34), chr(34) * 2)}"'
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(re.escape(normalized_keyword), flags)
    packed = bytearray((len(entries) + 7) // 8)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path)
        metadata = connection.execute(
            "SELECT schema_version, entry_count FROM index_metadata LIMIT 1"
        ).fetchone()
        if metadata != (INDEX_SCHEMA_VERSION, len(entries)):
            connection.close()
            connection = None
            return None
        cursor = connection.execute(
            "SELECT rowid FROM log_search WHERE log_search MATCH ?", (query,)
        )
        while True:
            if cancel_check is not None and cancel_check():
                raise InterruptedError("키워드 검색이 취소되었습니다.")
            rows = cursor.fetchmany(8192)
            if not rows:
                break
            for (rowid,) in rows:
                position = int(rowid) - 1
                if 0 <= position < len(entries) and pattern.search(
                    normalize_sxfy_w(entries[position].display_message)
                ):
                    packed[position >> 3] |= 1 << (position & 7)
    except InterruptedError:
        raise
    except (OSError, sqlite3.Error):
        return None
    finally:
        if connection is not None:
            connection.close()
    return int.from_bytes(packed, "little")

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Callable, Iterable

from gem300_log_analyzer.analysis.keyword_search import normalize_sxfy_w
from gem300_log_analyzer.models import LogEntry


INDEX_SCHEMA_VERSION = 2
INDEX_BATCH_SIZE = 10_000


def keyword_index_cache_key(
    paths: Iterable[Path | str],
    *,
    skip_setup_dump: bool,
    excluded_s6f11_ceid_ranges: Iterable[tuple[int, int]],
) -> str:
    files = []
    for path_value in paths:
        path = Path(path_value)
        try:
            stat = path.stat()
            files.append((str(path.resolve()), stat.st_size, stat.st_mtime_ns))
        except OSError:
            files.append((str(path), None, None))
    payload = {
        "schema": INDEX_SCHEMA_VERSION,
        "files": files,
        "skip_setup_dump": bool(skip_setup_dump),
        "excluded_s6f11_ceid_ranges": sorted(
            (int(start), int(end))
            for start, end in excluded_s6f11_ceid_ranges
        ),
        "content": "raw-message",
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def keyword_index_cache_path(cache_dir: Path | str, cache_key: str) -> Path:
    return Path(cache_dir) / f"keyword-search-{cache_key[:24]}.sqlite"


def is_keyword_index_valid(
    index_path: Path | str,
    entry_count: int,
    *,
    cache_key: str = "",
) -> bool:
    path = Path(index_path)
    if not path.is_file():
        return False
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path)
        metadata = connection.execute(
            "SELECT schema_version, entry_count, cache_key "
            "FROM index_metadata LIMIT 1"
        ).fetchone()
        return metadata == (INDEX_SCHEMA_VERSION, entry_count, cache_key)
    except (OSError, sqlite3.Error):
        return False
    finally:
        if connection is not None:
            connection.close()


def build_keyword_index(
    entries: Iterable[LogEntry],
    index_path: Path | str,
    *,
    cancel_check: Callable[[], bool] | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
    cache_key: str = "",
    reuse_existing: bool = False,
    raw_messages_only: bool = False,
) -> Path:
    """Build an atomic disk-backed trigram index for the current timeline."""
    entry_list = entries if isinstance(entries, list) else list(entries)
    destination = Path(index_path)
    if reuse_existing and is_keyword_index_valid(
        destination, len(entry_list), cache_key=cache_key
    ):
        if progress_callback is not None:
            progress_callback(len(entry_list), len(entry_list))
        return destination
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
            "CREATE TABLE index_metadata ("
            "schema_version INTEGER, entry_count INTEGER, cache_key TEXT)"
        )
        total = len(entry_list)
        for start in range(0, total, INDEX_BATCH_SIZE):
            if cancel_check is not None and cancel_check():
                raise InterruptedError("검색 인덱스 생성이 취소되었습니다.")
            batch = entry_list[start : start + INDEX_BATCH_SIZE]
            connection.executemany(
                "INSERT INTO log_search(rowid, message) VALUES (?, ?)",
                (
                    (
                        start + offset + 1,
                        normalize_sxfy_w(
                            entry.message
                            if raw_messages_only
                            else entry.display_message
                        ),
                    )
                    for offset, entry in enumerate(batch)
                ),
            )
            completed = start + len(batch)
            if progress_callback is not None:
                progress_callback(completed, total)
        connection.execute(
            "INSERT INTO index_metadata(schema_version, entry_count, cache_key) "
            "VALUES (?, ?, ?)",
            (INDEX_SCHEMA_VERSION, total, cache_key),
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
                if not 0 <= position < len(entries):
                    continue
                if not case_sensitive or pattern.search(
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

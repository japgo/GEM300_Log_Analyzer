"""Disk-backed storage helpers for large log analysis."""

from gem300_log_analyzer.storage.disk_text_store import (
    DiskTextRef,
    DiskTextWriter,
    close_disk_text_store,
    read_disk_text,
)

__all__ = [
    "DiskTextRef",
    "DiskTextWriter",
    "close_disk_text_store",
    "read_disk_text",
]

from __future__ import annotations

from gem300_log_analyzer.storage.disk_text_store import (
    DiskTextWriter,
    close_disk_text_store,
)


def test_disk_text_store_reads_utf8_slices_lazily(tmp_path) -> None:
    destination = tmp_path / "messages.texts"
    writer = DiskTextWriter(destination)
    first = writer.append("S6F11 원문")
    second = writer.append("\n두 번째 로그")
    writer.commit()

    assert first.read() == "S6F11 원문"
    assert second.read() == "\n두 번째 로그"

    close_disk_text_store(destination)

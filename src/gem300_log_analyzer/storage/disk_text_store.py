"""Append-only disk text storage with bounded lazy reads."""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


MAX_OPEN_TEXT_STORES = 8


@dataclass(frozen=True, slots=True)
class DiskTextRef:
    """A UTF-8 text slice stored in an immutable sidecar file."""

    path: str
    offset: int
    length: int

    def read(self) -> str:
        if self.length <= 0:
            return ""
        return _TEXT_STORE_CACHE.read(self)


@dataclass
class _OpenStore:
    handle: BinaryIO
    size: int
    modified_ns: int

    def close(self) -> None:
        self.handle.close()


class _TextStoreCache:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stores: OrderedDict[str, _OpenStore] = OrderedDict()

    def read(self, ref: DiskTextRef) -> str:
        with self._lock:
            store = self._open(ref.path)
            end = ref.offset + ref.length
            if ref.offset < 0 or end > store.size:
                raise ValueError(
                    f"원문 참조 범위가 올바르지 않습니다: {ref.path} "
                    f"{ref.offset}+{ref.length}/{store.size}"
                )
            store.handle.seek(ref.offset)
            data = store.handle.read(ref.length)
        return data.decode("utf-8", errors="replace")

    def _open(self, path_text: str) -> _OpenStore:
        path = Path(path_text)
        stat = path.stat()
        cached = self._stores.get(path_text)
        if cached is not None:
            if cached.size == stat.st_size and cached.modified_ns == stat.st_mtime_ns:
                self._stores.move_to_end(path_text)
                return cached
            cached.close()
            del self._stores[path_text]
        handle = path.open("rb")
        store = _OpenStore(handle, stat.st_size, stat.st_mtime_ns)
        self._stores[path_text] = store
        while len(self._stores) > MAX_OPEN_TEXT_STORES:
            _old_path, old_store = self._stores.popitem(last=False)
            old_store.close()
        return store

    def close(self, path: str | Path | None = None) -> None:
        with self._lock:
            if path is None:
                stores = list(self._stores.values())
                self._stores.clear()
            else:
                store = self._stores.pop(str(path), None)
                stores = [] if store is None else [store]
            for store in stores:
                store.close()


_TEXT_STORE_CACHE = _TextStoreCache()


class DiskTextWriter:
    """Write UTF-8 strings to a temporary file and atomically publish it."""

    def __init__(self, destination: Path | str) -> None:
        self.destination = Path(destination)
        self.path_text = str(self.destination)
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self.temporary = self.destination.with_name(
            f"{self.destination.name}.{uuid.uuid4().hex}.tmp"
        )
        self._handle = self.temporary.open("wb")
        self._offset = 0
        self._finished = False

    def append(self, text: str) -> DiskTextRef:
        data = text.encode("utf-8", errors="replace")
        ref = DiskTextRef(self.path_text, self._offset, len(data))
        self._handle.write(data)
        self._offset += len(data)
        return ref

    def commit(self) -> Path:
        if self._finished:
            return self.destination
        self._handle.flush()
        self._handle.close()
        close_disk_text_store(self.destination)
        self.temporary.replace(self.destination)
        self._finished = True
        return self.destination

    def abort(self) -> None:
        if self._finished:
            return
        self._handle.close()
        self.temporary.unlink(missing_ok=True)
        self._finished = True


def close_disk_text_store(path: str | Path | None = None) -> None:
    """Close cached mappings, primarily for replacement and test cleanup."""

    _TEXT_STORE_CACHE.close(path)


def read_disk_text(path: str, offset: int, length: int) -> str:
    """Read a UTF-8 slice without retaining it in the Python object graph."""

    return DiskTextRef(path, offset, length).read()

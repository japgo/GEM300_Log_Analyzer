from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

import yaml

from gem300_log_analyzer.models import LogEntry, LogType

MMI_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3})"
    r"\|(?P<color>\d+)\|(?P<seq>\d+)\|(?P<msg>.*)$"
)
COUNT_SUFFIX_RE = re.compile(r"-->\[Count:(\d+)\]\s*$")
INI_DUMP_START_RE = re.compile(r"\[.+?\.ini\] LOGGING", re.I)
INI_DUMP_FINISH_RE = re.compile(r"\[.+?\.ini\] FINISH", re.I)

DEFAULT_LEVEL_MAP: dict[int, str] = {
    0: "Normal",
    1: "Info",
    3: "Fail",
    6: "User",
    11: "SEQ",
    21: "CMS/GEM300",
    31: "Alarm",
}


def load_level_map(config_path: Optional[Path] = None) -> dict[int, str]:
    if config_path is None:
        config_path = Path(__file__).resolve().parents[3] / "config" / "level_map.yaml"
    if not config_path.exists():
        return DEFAULT_LEVEL_MAP.copy()
    with config_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    levels = data.get("levels", {})
    return {int(k): str(v) for k, v in levels.items()}


def _parse_timestamp(ts_text: str) -> datetime:
    return datetime.strptime(ts_text, "%Y-%m-%d %H:%M:%S:%f")


def _strip_count_suffix(message: str) -> tuple[str, Optional[int]]:
    match = COUNT_SUFFIX_RE.search(message)
    if not match:
        return message, None
    count = int(match.group(1))
    cleaned = COUNT_SUFFIX_RE.sub("", message).rstrip()
    return cleaned, count


def parse_mmi_log(
    text: str,
    source_file: str = "",
    skip_setup_dump: bool = True,
    level_map: Optional[dict[int, str]] = None,
) -> tuple[list[LogEntry], int]:
    """Parse MMI main log text into structured entries."""
    level_map = level_map or load_level_map()
    entries: list[LogEntry] = []
    skipped = 0
    in_setup_dump = False

    current: Optional[LogEntry] = None
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\n\r")
        match = MMI_LINE_RE.match(line)

        if match:
            if current is not None:
                if INI_DUMP_START_RE.search(current.message):
                    in_setup_dump = True
                elif INI_DUMP_FINISH_RE.search(current.message):
                    in_setup_dump = False
                if skip_setup_dump and (
                    in_setup_dump
                    or INI_DUMP_START_RE.search(current.message)
                    or INI_DUMP_FINISH_RE.search(current.message)
                ):
                    skipped += 1
                else:
                    current.is_setup_dump = in_setup_dump or INI_DUMP_START_RE.search(
                        current.message
                    ) is not None
                    entries.append(current)

            ts = _parse_timestamp(match.group("ts"))
            color_index = int(match.group("color"))
            seq_index = int(match.group("seq"))
            message, repeat_count = _strip_count_suffix(match.group("msg"))

            if INI_DUMP_START_RE.search(message):
                in_setup_dump = True
            elif INI_DUMP_FINISH_RE.search(message):
                in_setup_dump = False
            elif in_setup_dump and color_index != 1:
                in_setup_dump = False

            is_setup_dump = (
                in_setup_dump
                or INI_DUMP_START_RE.search(message) is not None
                or INI_DUMP_FINISH_RE.search(message) is not None
            )
            if skip_setup_dump and is_setup_dump:
                skipped += 1
                current = None
                continue

            current = LogEntry(
                timestamp=ts,
                log_type=LogType.MMI,
                source_file=source_file,
                message=message,
                line_no=line_no,
                color_index=color_index,
                seq_index=seq_index,
                level_name=level_map.get(color_index, f"Level{color_index}"),
                is_setup_dump=is_setup_dump,
                repeat_count=repeat_count,
                raw_line=line,
            )
        else:
            if current is None:
                continue
            if line.strip():
                current.message = f"{current.message}\n{line}"
                if INI_DUMP_START_RE.search(line):
                    in_setup_dump = True
                elif INI_DUMP_FINISH_RE.search(line):
                    in_setup_dump = False

    if current is not None:
        if INI_DUMP_START_RE.search(current.message):
            in_setup_dump = True
        elif INI_DUMP_FINISH_RE.search(current.message):
            in_setup_dump = False
        if skip_setup_dump and (
            in_setup_dump
            or INI_DUMP_START_RE.search(current.message)
            or INI_DUMP_FINISH_RE.search(current.message)
        ):
            skipped += 1
        else:
            current.is_setup_dump = in_setup_dump or INI_DUMP_START_RE.search(
                current.message
            ) is not None
            entries.append(current)

    return entries, skipped


def parse_mmi_file(
    path: Path | str,
    skip_setup_dump: bool = True,
    level_map: Optional[dict[int, str]] = None,
) -> tuple[list[LogEntry], int]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_mmi_log(
        text,
        source_file=path.name,
        skip_setup_dump=skip_setup_dump,
        level_map=level_map,
    )


def is_mmi_content(text: str, filename: str = "") -> bool:
    if MMI_LINE_RE.search(text[:5000]):
        return True
    if re.search(r"\d{4}_\d{2}_\d{2}\.log", filename, re.I):
        return True
    return False

"""Pure presentation and layout helpers for the desktop application."""

from __future__ import annotations

import difflib
import re
from datetime import date, datetime, timedelta
from xml.dom import minidom

from gem300_log_analyzer.models import LogEntry


XML_START_RE = re.compile(r"<([A-Za-z_][\w:.-]*)(?=[\s>/])")
SECS_ITEM_TAGS = {
    "L",
    "A",
    "B",
    "BOOLEAN",
    "I1",
    "I2",
    "I4",
    "I8",
    "U1",
    "U2",
    "U4",
    "U8",
    "F4",
    "F8",
}


def sxfy_label(match: re.Match[str]) -> str:
    return f"S{match.group('stream')}F{match.group('function')}".upper()


def format_log_time(value: datetime, include_date: bool = True) -> str:
    pattern = "%Y-%m-%d %H:%M:%S:%f" if include_date else "%H:%M:%S:%f"
    return value.strftime(pattern)[:-3]


def entry_to_values(
    entry: LogEntry,
    matched_keywords: str = "",
    bookmarked: bool = False,
    memo: str = "",
    time_delta: str = "",
    display_time: str | None = None,
    event_name: str | None = None,
    display_message: str | None = None,
) -> tuple[str, ...]:
    level_channel = entry.level_name or (
        f"CH {entry.channel}" if entry.channel is not None else ""
    )
    return (
        "★" if bookmarked else "",
        memo.replace("\n", " ")[:80],
        entry.display_time if display_time is None else display_time,
        time_delta,
        entry.log_type.value,
        matched_keywords,
        level_channel,
        "" if entry.ceid is None else str(entry.ceid),
        (entry.event_name or "") if event_name is None else event_name,
        entry.source_file,
        str(entry.line_no),
        (entry.display_message if display_message is None else display_message)
        .replace("\n", " | ")[:1000],
    )


def _pretty_xml_fragment(fragment: str) -> str | None:
    try:
        document = minidom.parseString(fragment.encode("utf-8"))
    except Exception:
        return None
    lines = [
        line
        for line in document.toprettyxml(indent="  ").splitlines()
        if line.strip() and not line.startswith("<?xml")
    ]
    return "\n".join(lines)


def format_xml_in_message(message: str) -> str:
    output: list[str] = []
    cursor = 0
    while cursor < len(message):
        match = XML_START_RE.search(message, cursor)
        if not match:
            output.append(message[cursor:])
            break

        tag_name = match.group(1)
        if tag_name.upper() in SECS_ITEM_TAGS:
            output.append(message[cursor : match.end()])
            cursor = match.end()
            continue

        close_token = f"</{tag_name}>"
        end_index = message.find(close_token, match.end())
        if end_index < 0:
            output.append(message[cursor : match.end()])
            cursor = match.end()
            continue

        fragment_end = end_index + len(close_token)
        fragment = message[match.start() : fragment_end]
        pretty_xml = _pretty_xml_fragment(fragment)
        if pretty_xml is None:
            output.append(message[cursor : match.end()])
            cursor = match.end()
            continue

        output.append(message[cursor : match.start()])
        output.append("\n--- XML ---\n")
        output.append(pretty_xml)
        output.append("\n--- XML END ---")
        cursor = fragment_end

    return "".join(output)


def calculate_flow_positions(
    item_widths: list[int], available_width: int, gap: int = 6
) -> list[tuple[int, int]]:
    """Return row/column positions while preserving the item order."""
    positions: list[tuple[int, int]] = []
    usable_width = max(1, int(available_width))
    row = 0
    column = 0
    used_width = 0
    for requested_width in item_widths:
        item_width = max(1, int(requested_width))
        next_width = item_width if column == 0 else gap + item_width
        if column > 0 and used_width + next_width > usable_width:
            row += 1
            column = 0
            used_width = 0
            next_width = item_width
        positions.append((row, column))
        used_width += next_width
        column += 1
    return positions


def layout_responsive_flow(frame, flow: dict, width: int | None = None) -> None:
    frame_width = int(width if width is not None else frame.winfo_width())
    if frame_width <= 1:
        return
    widgets = flow["widgets"]
    gap = int(flow["gap"])
    available_width = max(1, frame_width - int(flow["horizontal_padding"]))
    item_widths = [widget.winfo_reqwidth() for widget in widgets]
    item_heights = [widget.winfo_reqheight() for widget in widgets]
    positions = calculate_flow_positions(item_widths, available_width, gap)
    effective_widths = list(item_widths)
    stretch_index = flow.get("stretch_index")
    if isinstance(stretch_index, int) and 0 <= stretch_index < len(widgets):
        stretch_row = positions[stretch_index][0]
        row_indices = [
            index
            for index, (row, _column) in enumerate(positions)
            if row == stretch_row
        ]
        row_width = sum(item_widths[index] for index in row_indices)
        row_width += gap * max(0, len(row_indices) - 1)
        effective_widths[stretch_index] += max(0, available_width - row_width)
    layout_signature = (
        tuple(item_widths),
        tuple(item_heights),
        tuple(positions),
        tuple(effective_widths),
    )
    if layout_signature == flow["layout_signature"]:
        return

    row_gap = 4
    row_heights: dict[int, int] = {}
    for height, (row, _column) in zip(item_heights, positions):
        row_heights[row] = max(row_heights.get(row, 0), height)
    row_offsets: dict[int, int] = {}
    offset = 0
    for row in sorted(row_heights):
        row_offsets[row] = offset
        offset += row_heights[row] + row_gap
    total_height = max(1, offset - row_gap)

    x_offsets: dict[int, int] = {}
    for widget in widgets:
        widget.grid_forget()
        widget.place_forget()
    for index, (widget, width_needed, (row, _column)) in enumerate(
        zip(widgets, effective_widths, positions)
    ):
        x = x_offsets.get(row, 0)
        if index == stretch_index:
            widget.place(x=x, y=row_offsets[row], width=width_needed)
        else:
            widget.place(x=x, y=row_offsets[row])
        x_offsets[row] = x + width_needed + gap
    frame.configure(height=total_height)
    flow["layout_signature"] = layout_signature


def format_entries_for_clipboard(entries: list[LogEntry]) -> str:
    return "\n\n".join(format_entry_for_clipboard(entry) for entry in entries)


def format_entry_for_clipboard(
    entry: LogEntry, display_message: str | None = None
) -> str:
    message = entry.display_message if display_message is None else display_message
    if not entry.raw_line:
        return message
    raw_lines = entry.raw_line.splitlines()
    message_lines = message.splitlines()
    if not raw_lines or not message_lines:
        return entry.raw_line
    if raw_lines[0].endswith(message_lines[0]):
        prefix = raw_lines[0][: -len(message_lines[0])]
        return "\n".join([prefix + message_lines[0], *message_lines[1:]])
    return entry.raw_line


def format_time_filter_input(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def parse_time_filter_input(
    text: str, default_date: date
) -> tuple[datetime | None, bool]:
    value = text.strip()
    if not value:
        return None, False
    normalized = value.replace("T", " ")
    datetime_formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    )
    for fmt in datetime_formats:
        try:
            return datetime.strptime(normalized, fmt), True
        except ValueError:
            pass
    for fmt in ("%H:%M:%S.%f", "%H:%M:%S", "%H:%M"):
        try:
            parsed = datetime.strptime(normalized, fmt).time()
            return datetime.combine(default_date, parsed), False
        except ValueError:
            pass
    raise ValueError("시간 형식이 올바르지 않습니다.")


def parse_custom_time_filter_inputs(
    start_text: str, end_text: str, default_date: date
) -> tuple[datetime | None, datetime | None]:
    start, start_has_date = parse_time_filter_input(start_text, default_date)
    end, end_has_date = parse_time_filter_input(end_text, default_date)
    if start is None and end is None:
        raise ValueError("시작 시간 또는 종료 시간 중 하나 이상 입력하세요.")
    if start is not None and end is not None and end < start:
        if not start_has_date and not end_has_date:
            end += timedelta(days=1)
        else:
            raise ValueError("종료 시간이 시작 시간보다 빠릅니다.")
    return start, end


def format_time_delta(delta: timedelta) -> str:
    total_ms = int(round(delta.total_seconds() * 1000))
    sign = "-" if total_ms < 0 else "+"
    total_ms = abs(total_ms)
    if total_ms < 1000:
        return f"{sign}{total_ms}ms"
    if total_ms < 60_000:
        if total_ms % 1000 == 0:
            return f"{sign}{total_ms // 1000}s"
        return f"{sign}{total_ms / 1000:.1f}s"
    total_seconds = total_ms // 1000
    minutes, seconds = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{sign}{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{sign}{hours}h {minutes}m {seconds}s"


def aligned_line_diff(
    left_lines: list[str], right_lines: list[str]
) -> tuple[list[str], list[str], list[str], list[str]]:
    matcher = difflib.SequenceMatcher(None, left_lines, right_lines)
    aligned_left: list[str] = []
    aligned_right: list[str] = []
    left_marks: list[str] = []
    right_marks: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        left_chunk = left_lines[i1:i2]
        right_chunk = right_lines[j1:j2]
        if tag == "equal":
            aligned_left.extend(left_chunk)
            aligned_right.extend(right_chunk)
            left_marks.extend([""] * len(left_chunk))
            right_marks.extend([""] * len(right_chunk))
        elif tag == "replace":
            count = max(len(left_chunk), len(right_chunk))
            aligned_left.extend(left_chunk + [""] * (count - len(left_chunk)))
            aligned_right.extend(right_chunk + [""] * (count - len(right_chunk)))
            left_marks.extend(
                ["replace"] * len(left_chunk) + ["insert"] * (count - len(left_chunk))
            )
            right_marks.extend(
                ["replace"] * len(right_chunk) + ["delete"] * (count - len(right_chunk))
            )
        elif tag == "delete":
            aligned_left.extend(left_chunk)
            aligned_right.extend([""] * len(left_chunk))
            left_marks.extend(["delete"] * len(left_chunk))
            right_marks.extend(["insert"] * len(left_chunk))
        elif tag == "insert":
            aligned_left.extend([""] * len(right_chunk))
            aligned_right.extend(right_chunk)
            left_marks.extend(["delete"] * len(right_chunk))
            right_marks.extend(["insert"] * len(right_chunk))
    return aligned_left, aligned_right, left_marks, right_marks

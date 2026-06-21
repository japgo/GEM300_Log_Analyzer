from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from gem300_log_analyzer.db.report_variable_lookup import ReportVariable


SECS_ITEM_RE = re.compile(
    r"^(?P<indent>\s*)<(?P<type>[A-Z0-9]+)\s+\[(?P<count>\d+)\](?:\s+(?P<value>.*?))?\s*>"
)


@dataclass
class SecsNode:
    line_index: int
    indent: int
    item_type: str
    count: int
    value: str
    children: list["SecsNode"] = field(default_factory=list)


def _parse_secs_nodes(lines: list[str]) -> list[SecsNode]:
    roots: list[SecsNode] = []
    stack: list[SecsNode] = []
    for index, line in enumerate(lines):
        match = SECS_ITEM_RE.match(line)
        if not match:
            continue

        node = SecsNode(
            line_index=index,
            indent=len(match.group("indent")),
            item_type=match.group("type").upper(),
            count=int(match.group("count")),
            value=(match.group("value") or "").strip(),
        )
        while stack and stack[-1].indent >= node.indent:
            stack.pop()
        if stack:
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)
    return roots


def _node_int_value(node: SecsNode) -> int | None:
    match = re.search(r"-?\d+", node.value)
    if not match:
        return None
    return int(match.group(0))


def _walk_nodes(nodes: Iterable[SecsNode]) -> Iterable[SecsNode]:
    for node in nodes:
        yield node
        yield from _walk_nodes(node.children)


def _find_s6f11_body(roots: list[SecsNode]) -> SecsNode | None:
    for node in _walk_nodes(roots):
        if node.item_type == "L" and len(node.children) >= 3:
            return node
    return None


def extract_s6f11_rptids(message: str) -> set[int]:
    if "S6F11" not in message:
        return set()

    roots = _parse_secs_nodes(message.splitlines())
    body = _find_s6f11_body(roots)
    if body is None:
        return set()

    rptids: set[int] = set()
    report_list = body.children[2]
    for report_node in report_list.children:
        if report_node.item_type != "L" or len(report_node.children) < 2:
            continue
        rptid = _node_int_value(report_node.children[0])
        if rptid is not None:
            rptids.add(rptid)
    return rptids


def annotate_s6f11_variables(
    message: str,
    report_variables: Mapping[int, list[ReportVariable]],
) -> str:
    if "S6F11" not in message or not report_variables:
        return message

    lines = message.splitlines()
    roots = _parse_secs_nodes(lines)
    body = _find_s6f11_body(roots)
    if body is None:
        return message

    annotations: dict[int, str] = {}
    report_list = body.children[2]
    for report_node in report_list.children:
        if report_node.item_type != "L" or len(report_node.children) < 2:
            continue

        rptid = _node_int_value(report_node.children[0])
        if rptid is None:
            continue

        variables = report_variables.get(rptid, [])
        value_list = report_node.children[1]
        for value_node, variable in zip(value_list.children, variables):
            suffix = f" // ({variable.vid}) {variable.name}".rstrip()
            annotations[value_node.line_index] = suffix

    if not annotations:
        return message

    annotated_lines = []
    for index, line in enumerate(lines):
        suffix = annotations.get(index)
        annotated_lines.append(line + suffix if suffix else line)
    return "\n".join(annotated_lines)

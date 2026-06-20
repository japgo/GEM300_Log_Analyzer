from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pyodbc

from gem300_log_analyzer.db.event_lookup import build_connection_string


@dataclass(frozen=True)
class ReportVariable:
    rptid: int
    index_no: int
    vid: int
    name: str


def load_report_variables(
    rptids: Iterable[int],
    server: str = "localhost",
    database: str = "BOCCOB_BONDER",
    driver: str = "ODBC Driver 17 for SQL Server",
) -> dict[int, list[ReportVariable]]:
    unique_rptids = sorted({int(rptid) for rptid in rptids if rptid is not None})
    if not unique_rptids:
        return {}

    result: dict[int, list[ReportVariable]] = {}
    connection_string = build_connection_string(server, database, driver)
    with pyodbc.connect(connection_string, timeout=3) as conn:
        cursor = conn.cursor()
        for offset in range(0, len(unique_rptids), 500):
            chunk = unique_rptids[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = cursor.execute(
                f"""
                SELECT rv.RepId, rv.Index_No, rv.VId, v.Name
                FROM ReportVariables rv
                LEFT JOIN Variables v ON v.VId = rv.VId
                WHERE rv.RepId IN ({placeholders})
                ORDER BY rv.RepId, rv.Index_No
                """,
                chunk,
            ).fetchall()
            for row in rows:
                rptid = int(row.RepId)
                result.setdefault(rptid, []).append(
                    ReportVariable(
                        rptid=rptid,
                        index_no=int(row.Index_No),
                        vid=int(row.VId),
                        name="" if row.Name is None else str(row.Name).strip(),
                    )
                )
    return result

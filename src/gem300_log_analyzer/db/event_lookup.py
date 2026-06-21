from __future__ import annotations

from typing import Iterable

import pyodbc


DEFAULT_DRIVER = "ODBC Driver 17 for SQL Server"
DEFAULT_SERVER = "localhost"
DEFAULT_DATABASE = "BOCCOB_BONDER"


def build_connection_string(
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
    driver: str = DEFAULT_DRIVER,
) -> str:
    return (
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        "Trusted_Connection=yes;"
        "TrustServerCertificate=yes;"
    )


def load_event_names(
    ceids: Iterable[int],
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
    driver: str = DEFAULT_DRIVER,
) -> dict[int, str]:
    unique_ceids = sorted({int(ceid) for ceid in ceids if ceid is not None})
    if not unique_ceids:
        return {}

    result: dict[int, str] = {}
    connection_string = build_connection_string(server, database, driver)
    with pyodbc.connect(connection_string, timeout=3) as conn:
        cursor = conn.cursor()
        for offset in range(0, len(unique_ceids), 500):
            chunk = unique_ceids[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = cursor.execute(
                f"""
                SELECT CEId, Name
                FROM [Events]
                WHERE CEId IN ({placeholders})
                """,
                chunk,
            ).fetchall()
            result.update({int(row.CEId): str(row.Name).strip() for row in rows})
    return result


def load_all_event_names(
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
    driver: str = DEFAULT_DRIVER,
) -> dict[int, str]:
    result: dict[int, str] = {}
    connection_string = build_connection_string(server, database, driver)
    with pyodbc.connect(connection_string, timeout=3) as conn:
        rows = conn.cursor().execute(
            """
            SELECT CEId, Name
            FROM [Events]
            WHERE CEId IS NOT NULL
            """
        ).fetchall()
        result.update(
            {
                int(row.CEId): "" if row.Name is None else str(row.Name).strip()
                for row in rows
            }
        )
    return result


def search_events(
    term: str,
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
    driver: str = DEFAULT_DRIVER,
    limit: int = 100,
) -> list[tuple[int, str]]:
    keyword = term.strip()
    if not keyword:
        return []

    limit = max(1, min(500, int(limit)))
    like = f"%{keyword}%"
    result: list[tuple[int, str]] = []
    connection_string = build_connection_string(server, database, driver)
    with pyodbc.connect(connection_string, timeout=3) as conn:
        rows = conn.cursor().execute(
            f"""
            SELECT TOP {limit} CEId, Name
            FROM [Events]
            WHERE CEId IS NOT NULL
              AND (
                  CONVERT(varchar(32), CEId) LIKE ?
                  OR Name LIKE ?
              )
            ORDER BY CEId
            """,
            like,
            like,
        ).fetchall()
        result.extend(
            (
                int(row.CEId),
                "" if row.Name is None else str(row.Name).strip(),
            )
            for row in rows
        )
    return result


def load_database_names(
    server: str = DEFAULT_SERVER,
    driver: str = DEFAULT_DRIVER,
) -> list[str]:
    connection_string = build_connection_string(server, "master", driver)
    with pyodbc.connect(connection_string, timeout=3) as conn:
        rows = conn.cursor().execute(
            """
            SELECT name
            FROM sys.databases
            WHERE state_desc = 'ONLINE'
            ORDER BY name
            """
        ).fetchall()
    return [str(row.name) for row in rows]

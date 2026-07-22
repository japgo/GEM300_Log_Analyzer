from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp


def test_analysis_file_rows_keep_path_order_and_type() -> None:
    paths = [
        "/logs/2026_07_22.log",
        "/logs/2026-07-22 18.log",
    ]
    file_types = {
        "2026_07_22.log": "MMI",
        "2026-07-22 18.log": "SECS",
    }

    assert Gem300DesktopApp._analysis_file_rows(paths, file_types) == [
        (1, "MMI", "2026_07_22.log", "/logs/2026_07_22.log"),
        (2, "SECS", "2026-07-22 18.log", "/logs/2026-07-22 18.log"),
    ]


def test_analysis_file_rows_mark_unrecognized_file_type() -> None:
    assert Gem300DesktopApp._analysis_file_rows(["/logs/raw.log"], {}) == [
        (1, "UNKNOWN", "raw.log", "/logs/raw.log")
    ]

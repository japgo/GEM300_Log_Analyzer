"""Tkinter desktop UI for GEM300 Log Analyzer."""

from __future__ import annotations

import csv
import ctypes
import difflib
import json
import os
import re
import sys
import threading
import traceback
from pathlib import Path
from tkinter import (
    BooleanVar,
    Canvas,
    IntVar,
    Listbox,
    Menu,
    PhotoImage,
    StringVar,
    Text,
    Tk,
    Toplevel,
    filedialog,
    messagebox,
    simpledialog,
)
from tkinter import ttk
from xml.dom import minidom

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
APP_ICON_PNG = ROOT / "assets" / "app_icon.png"
APP_ICON_ICO = ROOT / "assets" / "app_icon.ico"
WINDOWS_APP_ID = "BOC.GEM300LogAnalyzer.Desktop"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gem300_log_analyzer.analysis.alarm_summary import extract_alarms, summarize_alarms
from gem300_log_analyzer.analysis.gem300_trace import extract_gem300_events
from gem300_log_analyzer.analysis.keyword_search import search_multiple_keywords
from gem300_log_analyzer.db.event_lookup import (
    DEFAULT_DATABASE,
    DEFAULT_DRIVER,
    DEFAULT_SERVER,
    load_all_event_names,
    load_database_names,
    search_events,
)
from gem300_log_analyzer.db.report_variable_lookup import (
    ReportVariable,
    load_all_report_variables,
)
from gem300_log_analyzer.export.report_export import generate_report
from gem300_log_analyzer.models import LogEntry, SearchMatch
from gem300_log_analyzer.parsers.log_loader import count_text_lines, parse_paths

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None


COLUMNS = (
    "bookmark",
    "memo",
    "time",
    "type",
    "matched_keywords",
    "level_channel",
    "ceid",
    "event_name",
    "file",
    "line",
    "message",
)

COLUMN_LABELS = {
    "bookmark": "북마크",
    "memo": "메모",
    "time": "시간",
    "type": "로그타입",
    "matched_keywords": "매칭 키워드",
    "level_channel": "레벨/채널",
    "ceid": "CEID",
    "event_name": "이벤트명",
    "file": "파일",
    "line": "라인",
    "message": "메시지",
}

COLUMN_WIDTHS = {
    "bookmark": 70,
    "memo": 160,
    "time": 160,
    "type": 70,
    "matched_keywords": 160,
    "level_channel": 90,
    "ceid": 80,
    "event_name": 220,
    "file": 170,
    "line": 70,
    "message": 620,
}
DETAIL_FONT_VALUES = (
    "Consolas",
    "Courier New",
    "Malgun Gothic",
    "Arial",
)
APP_CONFIG_DIR = Path(
    os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
) / "GEM300LogAnalyzer"
APP_CONFIG_PATH = APP_CONFIG_DIR / "desktop_settings.json"
THEMES = {
    "light": {
        "bg": "#f6f8fb",
        "panel": "#ffffff",
        "text": "#17202a",
        "muted": "#475569",
        "field": "#ffffff",
        "border": "#cbd5e1",
        "accent": "#00a6c8",
        "select_bg": "#d9f3ff",
        "select_fg": "#0f172a",
        "tree_bg": "#ffffff",
        "tree_alt": "#fff7cc",
        "detail_bg": "#fbfdff",
        "detail_fg": "#111827",
        "highlight_bg": "#fff176",
        "highlight_fg": "#111827",
        "compare_change_bg": "#fff3b0",
        "compare_delete_bg": "#ffd6d6",
        "compare_insert_bg": "#d8f5d0",
        "compare_char_diff_fg": "#dc2626",
        "grip_bg": "#e5e7eb",
        "grip_line": "#94a3b8",
        "grip_dot": "#475569",
    },
    "dark": {
        "bg": "#0f172a",
        "panel": "#111827",
        "text": "#e5edf5",
        "muted": "#b8c3cf",
        "field": "#0b1220",
        "border": "#334155",
        "accent": "#22d3ee",
        "select_bg": "#164e63",
        "select_fg": "#f8fafc",
        "tree_bg": "#0b1220",
        "tree_alt": "#3f3414",
        "detail_bg": "#08111f",
        "detail_fg": "#e5edf5",
        "highlight_bg": "#facc15",
        "highlight_fg": "#0f172a",
        "compare_change_bg": "#5a4b18",
        "compare_delete_bg": "#5a2028",
        "compare_insert_bg": "#244a2b",
        "compare_char_diff_fg": "#ff6b6b",
        "grip_bg": "#1f2937",
        "grip_line": "#64748b",
        "grip_dot": "#cbd5e1",
    },
}

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
SXFy_RE = re.compile(r"\bS(?P<stream>\d+)F(?P<function>\d+)(?:W)?\b", re.IGNORECASE)


def _sxfy_label(match: re.Match) -> str:
    return f"S{match.group('stream')}F{match.group('function')}".upper()


def _entry_to_values(
    entry: LogEntry,
    matched_keywords: str = "",
    bookmarked: bool = False,
    memo: str = "",
) -> tuple[str, ...]:
    level_channel = entry.level_name or (
        f"CH {entry.channel}" if entry.channel is not None else ""
    )
    return (
        "★" if bookmarked else "",
        memo.replace("\n", " ")[:80],
        entry.display_time,
        entry.log_type.value,
        matched_keywords,
        level_channel,
        "" if entry.ceid is None else str(entry.ceid),
        entry.event_name or "",
        entry.source_file,
        str(entry.line_no),
        entry.message.replace("\n", " | ")[:1000],
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


def _format_xml_in_message(message: str) -> str:
    output: list[str] = []
    cursor = 0
    while cursor < len(message):
        match = XML_START_RE.search(message, cursor)
        if not match:
            output.append(message[cursor:])
            break

        tag_name = match.group(1)
        if tag_name.upper() in SECS_ITEM_TAGS:
            output.append(message[cursor:match.end()])
            cursor = match.end()
            continue

        close_token = f"</{tag_name}>"
        end_index = message.find(close_token, match.end())
        if end_index < 0:
            output.append(message[cursor:match.end()])
            cursor = match.end()
            continue

        fragment_end = end_index + len(close_token)
        fragment = message[match.start() : fragment_end]
        pretty_xml = _pretty_xml_fragment(fragment)
        if pretty_xml is None:
            output.append(message[cursor:match.end()])
            cursor = match.end()
            continue

        output.append(message[cursor:match.start()])
        output.append("\n--- XML ---\n")
        output.append(pretty_xml)
        output.append("\n--- XML END ---")
        cursor = fragment_end

    return "".join(output)


class Gem300DesktopApp:
    def __init__(self) -> None:
        self._set_windows_app_id()
        self.root = TkinterDnD.Tk() if TkinterDnD is not None else Tk()
        self.root.title("GEM300 Log Analyzer")
        self._set_window_icon()
        self.root.geometry("1400x820")
        self.root.minsize(1050, 640)
        self.root.after(0, self._maximize_window)

        self.paths: list[str] = []
        self.entries: list[LogEntry] = []
        self.filtered_entries: list[LogEntry] = []
        self.search_matches: list[SearchMatch] = []
        self.log_view_layout_active = False
        self.skipped_setup_lines = 0
        self.file_types: dict[str, str] = {}
        self.gem300_events = []
        self.alarms = []
        self.report_variables: dict[int, list[ReportVariable]] = {}
        self.settings = self._load_settings()
        self.bookmarks: dict[str, str] = self._load_bookmarks()
        self.sxfy_types: list[str] = []
        self.sxfy_filter_vars: dict[str, BooleanVar] = {}

        self.keyword_var = StringVar()
        self.keyword_mode_var = StringVar(value="AND")
        self.exclude_keyword_var = StringVar()
        self.preset_name_var = StringVar()
        saved_theme = str(self.settings.get("theme", "light")).lower()
        self.theme_var = StringVar(value=saved_theme if saved_theme in THEMES else "light")
        self.keywords: list[tuple[str, str]] = []
        self.exclude_keywords: list[str] = []
        self.selected_keyword_index: int | None = None
        self.selected_exclude_keyword_index: int | None = None
        self.search_presets: dict[str, dict] = self._load_search_presets()
        self.matched_keywords_by_entry: dict[int, str] = {}
        self.case_sensitive_var = BooleanVar(value=False)
        self.regex_search_var = BooleanVar(value=False)
        self.filter_mmi_var = BooleanVar(value=True)
        self.filter_secs_var = BooleanVar(value=True)
        self.skip_setup_var = BooleanVar(value=True)
        self.db_annotation_var = BooleanVar(
            value=bool(self.settings.get("db_annotation_enabled", True))
        )
        self.db_server_var = StringVar(
            value=str(self.settings.get("db_server", DEFAULT_SERVER))
        )
        self.db_database_var = StringVar(
            value=str(self.settings.get("db_database", DEFAULT_DATABASE))
        )
        self.db_driver_var = StringVar(
            value=str(self.settings.get("db_driver", DEFAULT_DRIVER))
        )
        saved_db_values = self.settings.get("db_database_values", [])
        self.db_database_values = [
            str(name)
            for name in saved_db_values
            if isinstance(saved_db_values, list) and str(name).strip()
        ]
        if self.db_database_var.get() not in self.db_database_values:
            self.db_database_values.insert(0, self.db_database_var.get())
        self.exclude_s6f11_var = BooleanVar(
            value=bool(self.settings.get("exclude_s6f11_enabled", True))
        )
        self.exclude_ceid_var = StringVar(
            value=str(self.settings.get("exclude_s6f11_ceid_ranges", "411001-411604"))
        )
        self.exclude_ceid_items = self._load_exclude_ceid_items()
        self.exclude_ceid_summary_var = StringVar(value=self._exclude_ceid_summary())
        self.detail_horizontal_var = BooleanVar(value=False)
        self.detail_wrap_var = BooleanVar(value=True)
        self.detail_header_var = BooleanVar(
            value=bool(self.settings.get("detail_header_enabled", True))
        )
        self.compare_mode_var = BooleanVar(
            value=bool(self.settings.get("compare_mode_enabled", False))
        )
        saved_detail_font = str(self.settings.get("detail_font_family", "Consolas"))
        if saved_detail_font not in DETAIL_FONT_VALUES:
            saved_detail_font = "Consolas"
        self.detail_font_family_var = StringVar(value=saved_detail_font)
        try:
            saved_detail_font_size = int(self.settings.get("detail_font_size", 10))
        except (TypeError, ValueError):
            saved_detail_font_size = 10
        self.detail_font_size_var = IntVar(
            value=max(7, min(32, saved_detail_font_size))
        )
        self.context_rows_var = IntVar(value=int(self.settings.get("context_rows", 0)))
        self.display_rows_var = IntVar(value=5000)
        self.status_var = StringVar(value="로그 파일을 선택하세요.")
        self.summary_var = StringVar(value="")
        self.progress_percent_var = StringVar(value="")
        self.visible_columns = self._load_visible_columns()
        self.column_visible_vars: dict[str, BooleanVar] = {
            column: BooleanVar(value=column in self.visible_columns)
            for column in COLUMNS
        }

        self._build_ui()

    def _set_windows_app_id(self) -> None:
        if sys.platform != "win32":
            return
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(WINDOWS_APP_ID)
        except Exception:
            pass

    def _set_window_icon(self) -> None:
        self.window_icon_image = None
        try:
            if APP_ICON_ICO.exists():
                self.root.iconbitmap(default=str(APP_ICON_ICO))
        except Exception:
            pass
        try:
            if APP_ICON_PNG.exists():
                self.window_icon_image = PhotoImage(file=str(APP_ICON_PNG))
                self.root.iconphoto(True, self.window_icon_image)
        except Exception:
            pass

    def _maximize_window(self) -> None:
        try:
            self.root.state("zoomed")
        except Exception:
            try:
                self.root.attributes("-zoomed", True)
            except Exception:
                pass

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(5, weight=1)

        self.toolbar_frame = ttk.Frame(self.root, padding=(10, 8))
        self.toolbar_frame.grid(row=0, column=0, sticky="ew")
        self.toolbar_frame.columnconfigure(10, weight=1)

        ttk.Button(self.toolbar_frame, text="파일 선택", command=self.choose_files).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(self.toolbar_frame, text="분석", command=self.analyze).grid(
            row=0, column=1, padx=(0, 14)
        )

        ttk.Checkbutton(
            self.toolbar_frame,
            text="MMI",
            variable=self.filter_mmi_var,
            command=self.apply_filters,
        ).grid(row=0, column=2, padx=(0, 6))
        ttk.Checkbutton(
            self.toolbar_frame,
            text="SECS/GEM",
            variable=self.filter_secs_var,
            command=self.apply_filters,
        ).grid(row=0, column=3, padx=(0, 12))
        ttk.Checkbutton(
            self.toolbar_frame,
            text="Setup.ini 덤프 제외",
            variable=self.skip_setup_var,
        ).grid(row=0, column=4, padx=(0, 12))

        ttk.Label(self.toolbar_frame, text="포함 키워드").grid(row=0, column=5, padx=(0, 4))
        keyword_entry = ttk.Entry(
            self.toolbar_frame, textvariable=self.keyword_var, width=24
        )
        keyword_entry.grid(row=0, column=6, padx=(0, 6))
        keyword_entry.bind("<Return>", lambda _event: self.add_keyword())
        ttk.Combobox(
            self.toolbar_frame,
            textvariable=self.keyword_mode_var,
            values=("AND", "OR"),
            width=5,
            state="readonly",
        ).grid(row=0, column=7, padx=(0, 6))
        ttk.Button(self.toolbar_frame, text="추가/수정", command=self.add_keyword).grid(
            row=0, column=8, padx=(0, 6)
        )
        ttk.Checkbutton(
            self.toolbar_frame,
            text="대소문자 구분",
            variable=self.case_sensitive_var,
            command=self.apply_filters,
        ).grid(row=0, column=9, padx=(0, 12))
        ttk.Checkbutton(
            self.toolbar_frame,
            text="정규식 검색",
            variable=self.regex_search_var,
            command=self.apply_filters,
        ).grid(row=1, column=8, padx=(0, 12), pady=(6, 0))
        ttk.Button(
            self.toolbar_frame, text="검색/필터 적용", command=self.apply_filters
        ).grid(row=0, column=10, sticky="w")
        ttk.Label(self.toolbar_frame, text="프리셋").grid(
            row=1, column=9, padx=(0, 4), pady=(6, 0), sticky="e"
        )
        preset_frame = ttk.Frame(self.toolbar_frame)
        preset_frame.grid(row=1, column=10, padx=(0, 0), pady=(6, 0), sticky="w")
        ttk.Entry(preset_frame, textvariable=self.preset_name_var, width=18).grid(
            row=0, column=0, padx=(0, 6), sticky="w"
        )
        ttk.Button(preset_frame, text="저장", command=self.save_search_preset).grid(
            row=0, column=1, padx=(0, 6)
        )
        preset_button = ttk.Menubutton(preset_frame, text="불러오기")
        preset_button.grid(row=0, column=2, padx=(0, 6))
        self.preset_menu = Menu(preset_button, tearoff=False)
        preset_button["menu"] = self.preset_menu
        ttk.Button(preset_frame, text="삭제", command=self.delete_search_preset).grid(
            row=0, column=3
        )
        self._build_preset_menu()
        ttk.Label(self.toolbar_frame, text="제외 키워드").grid(
            row=1, column=5, padx=(0, 4), pady=(6, 0)
        )
        exclude_keyword_entry = ttk.Entry(
            self.toolbar_frame, textvariable=self.exclude_keyword_var, width=24
        )
        exclude_keyword_entry.grid(row=1, column=6, padx=(0, 6), pady=(6, 0))
        exclude_keyword_entry.bind("<Return>", lambda _event: self.add_exclude_keyword())
        ttk.Button(self.toolbar_frame, text="추가", command=self.add_exclude_keyword).grid(
            row=1, column=7, padx=(0, 6), pady=(6, 0)
        )

        self.actions_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        self.actions_frame.grid(row=1, column=0, sticky="ew")
        self.actions_frame.columnconfigure(5, weight=1)
        ttk.Label(self.actions_frame, text="표시 행").grid(row=0, column=0, padx=(0, 4))
        ttk.Spinbox(
            self.actions_frame,
            from_=100,
            to=100000,
            increment=100,
            textvariable=self.display_rows_var,
            width=8,
            command=self.refresh_table,
        ).grid(row=0, column=1, padx=(0, 12))
        ttk.Checkbutton(
            self.actions_frame,
            text="S6F11 CEID 제외",
            variable=self.exclude_s6f11_var,
            command=self.save_s6f11_exclude_settings,
        ).grid(row=0, column=2, padx=(0, 4))
        ttk.Label(
            self.actions_frame,
            textvariable=self.exclude_ceid_summary_var,
            width=18,
            anchor="w",
        ).grid(row=0, column=3, padx=(0, 6), sticky="w")
        ttk.Button(
            self.actions_frame,
            text="CEID 편집",
            command=self.open_ceid_exclude_editor,
        ).grid(row=0, column=4, padx=(0, 12))
        ttk.Label(self.actions_frame, textvariable=self.summary_var).grid(
            row=0, column=5, sticky="w"
        )
        ttk.Button(self.actions_frame, text="CSV 저장", command=self.export_csv).grid(
            row=0, column=6, padx=(8, 6)
        )
        ttk.Button(self.actions_frame, text="리포트 저장", command=self.export_report).grid(
            row=0, column=7, padx=(0, 6)
        )
        ttk.Button(self.actions_frame, text="초기화", command=self.reset_analysis).grid(
            row=0, column=8, padx=(0, 6)
        )
        column_button = ttk.Menubutton(self.actions_frame, text="컬럼 설정")
        column_button.grid(row=0, column=9, padx=(0, 6))
        self.column_menu = Menu(column_button, tearoff=False)
        column_button["menu"] = self.column_menu
        self._build_column_menu()
        self.sxfy_button = ttk.Menubutton(self.actions_frame, text="SxFy 필터")
        self.sxfy_button.grid(row=0, column=10, padx=(0, 12))
        self.sxfy_menu = Menu(self.sxfy_button, tearoff=False)
        self.sxfy_button["menu"] = self.sxfy_menu
        self._build_sxfy_menu()
        ttk.Label(self.actions_frame, text="테마").grid(row=0, column=11, padx=(0, 4))
        ttk.Combobox(
            self.actions_frame,
            textvariable=self.theme_var,
            values=("light", "dark"),
            width=7,
            state="readonly",
        ).grid(row=0, column=12)
        self.theme_var.trace_add("write", lambda *_args: self.on_theme_changed())

        self.db_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        self.db_frame.grid(row=2, column=0, sticky="ew")
        self.db_frame.columnconfigure(8, weight=1)
        ttk.Checkbutton(
            self.db_frame,
            text="DB 주석 사용",
            variable=self.db_annotation_var,
            command=self.save_db_settings,
        ).grid(row=0, column=0, padx=(0, 10))
        ttk.Label(self.db_frame, text="서버").grid(row=0, column=1, padx=(0, 4))
        db_server_entry = ttk.Entry(
            self.db_frame, textvariable=self.db_server_var, width=18
        )
        db_server_entry.grid(row=0, column=2, padx=(0, 10))
        ttk.Label(self.db_frame, text="DB").grid(row=0, column=3, padx=(0, 4))
        self.db_database_combo = ttk.Combobox(
            self.db_frame,
            textvariable=self.db_database_var,
            values=self.db_database_values,
            width=22,
        )
        self.db_database_combo.grid(row=0, column=4, padx=(0, 8))
        ttk.Button(
            self.db_frame, text="DB 목록", command=self.load_database_list
        ).grid(row=0, column=5, padx=(0, 12))
        ttk.Label(self.db_frame, text="ODBC").grid(row=0, column=6, padx=(0, 4))
        db_driver_entry = ttk.Entry(
            self.db_frame, textvariable=self.db_driver_var, width=24
        )
        db_driver_entry.grid(row=0, column=7, padx=(0, 12))
        ttk.Label(
            self.db_frame,
            text="분석 시작 전에 Events / ReportVariables / Variables를 메모리에 먼저 로드합니다.",
        ).grid(row=0, column=8, sticky="w")
        for entry in (db_server_entry, db_driver_entry):
            entry.bind("<FocusOut>", lambda _event: self.save_db_settings())
            entry.bind("<Return>", lambda _event: self.save_db_settings())
        self.db_database_combo.bind("<FocusOut>", lambda _event: self.save_db_settings())
        self.db_database_combo.bind("<Return>", lambda _event: self.save_db_settings())
        self.db_database_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self.save_db_settings()
        )

        self.keyword_panel = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        self.keyword_panel.grid(row=3, column=0, sticky="ew")
        self.keyword_panel.columnconfigure(0, weight=1)
        self.keyword_panel.columnconfigure(1, weight=1)

        include_panel = ttk.Frame(self.keyword_panel)
        include_panel.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        include_panel.columnconfigure(0, weight=1)
        ttk.Label(include_panel, text="포함 키워드 목록 (AND / OR)").grid(
            row=0, column=0, sticky="w"
        )
        self.keyword_tag_text = Text(
            include_panel,
            height=3,
            wrap="word",
            borderwidth=1,
            relief="solid",
            cursor="hand2",
        )
        self.keyword_tag_text.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        self.keyword_tag_text.bind("<Delete>", self.remove_selected_keyword)
        include_buttons = ttk.Frame(include_panel)
        include_buttons.grid(row=2, column=0, sticky="e")
        ttk.Button(
            include_buttons, text="선택 삭제", command=self.remove_selected_keyword
        ).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(include_buttons, text="전체 삭제", command=self.clear_keywords).grid(
            row=0, column=1
        )

        exclude_panel = ttk.Frame(self.keyword_panel)
        exclude_panel.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        exclude_panel.columnconfigure(0, weight=1)
        ttk.Label(exclude_panel, text="제외 키워드 목록 (하나라도 있으면 제외)").grid(
            row=0, column=0, sticky="w"
        )
        self.exclude_keyword_tag_text = Text(
            exclude_panel,
            height=3,
            wrap="word",
            borderwidth=1,
            relief="solid",
            cursor="hand2",
        )
        self.exclude_keyword_tag_text.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        self.exclude_keyword_tag_text.bind(
            "<Delete>", self.remove_selected_exclude_keyword
        )
        exclude_buttons = ttk.Frame(exclude_panel)
        exclude_buttons.grid(row=2, column=0, sticky="e")
        ttk.Button(
            exclude_buttons,
            text="선택 삭제",
            command=self.remove_selected_exclude_keyword,
        ).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(
            exclude_buttons, text="전체 삭제", command=self.clear_exclude_keywords
        ).grid(row=0, column=1)

        self.drop_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        self.drop_frame.grid(row=4, column=0, sticky="ew")
        self.drop_frame.columnconfigure(0, weight=1)
        drop_text = (
            "로그 파일을 여기에 드래그앤드롭하면 목록에 추가됩니다."
            if TkinterDnD is not None
            else "드래그앤드롭을 사용하려면 tkinterdnd2 패키지가 필요합니다. 파일 선택 버튼은 사용할 수 있습니다."
        )
        self.drop_label = ttk.Label(
            self.drop_frame,
            text=drop_text,
            relief="groove",
            anchor="center",
            padding=(10, 8),
        )
        self.drop_label.grid(row=0, column=0, sticky="ew")

        self.content_pane = ttk.PanedWindow(self.root, orient="vertical")
        self.content_pane.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 8))

        self.table_frame = ttk.Frame(self.content_pane)
        self.table_frame.columnconfigure(0, weight=1)
        self.table_frame.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            self.table_frame,
            columns=COLUMNS,
            show="headings",
            selectmode="extended",
        )
        for column in COLUMNS:
            self.tree.heading(column, text=COLUMN_LABELS[column])
            self.tree.column(
                column,
                width=COLUMN_WIDTHS[column],
                minwidth=50,
                stretch=column == "message",
                anchor="w",
            )
        self._apply_visible_columns(save=False)
        y_scroll = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(self.table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.tag_configure("bookmarked", background="#fff7cc")
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_detail)
        self.content_pane.add(self.table_frame, weight=4)

        self.detail_frame = ttk.Frame(self.content_pane)
        self.detail_frame.columnconfigure(0, weight=1)
        self.detail_frame.rowconfigure(2, weight=1)
        self.splitter_grip = Canvas(
            self.detail_frame,
            height=16,
            highlightthickness=0,
            bd=0,
            cursor="sb_v_double_arrow",
            background="#e5e7eb",
        )
        self.splitter_grip.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.splitter_grip.bind("<Configure>", self._draw_splitter_grip)
        self.splitter_grip.bind("<B1-Motion>", self._drag_main_splitter)
        detail_header = ttk.Frame(self.detail_frame)
        detail_header.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        detail_header.columnconfigure(0, weight=1)
        ttk.Label(detail_header, text="선택 로그 상세").grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(
            detail_header,
            text="상세 가로 보기",
            variable=self.detail_horizontal_var,
            command=self.show_selected_detail,
        ).grid(row=0, column=1, padx=(8, 0))
        ttk.Checkbutton(
            detail_header,
            text="긴 로그 줄바꿈",
            variable=self.detail_wrap_var,
            command=self.show_selected_detail,
        ).grid(row=0, column=2, padx=(8, 0))
        ttk.Checkbutton(
            detail_header,
            text="헤더 표시",
            variable=self.detail_header_var,
            command=self.on_detail_header_changed,
        ).grid(row=0, column=3, padx=(8, 0))
        ttk.Checkbutton(
            detail_header,
            text="비교 보기",
            variable=self.compare_mode_var,
            command=self.on_compare_mode_changed,
        ).grid(row=0, column=4, padx=(8, 0))
        ttk.Label(detail_header, text="앞뒤").grid(row=0, column=5, padx=(12, 2))
        ttk.Spinbox(
            detail_header,
            from_=0,
            to=200,
            increment=1,
            textvariable=self.context_rows_var,
            width=5,
            command=self.on_context_rows_changed,
        ).grid(row=0, column=6)
        ttk.Label(detail_header, text="폰트").grid(row=0, column=7, padx=(12, 2))
        self.detail_font_combo = ttk.Combobox(
            detail_header,
            textvariable=self.detail_font_family_var,
            values=DETAIL_FONT_VALUES,
            width=14,
            state="readonly",
        )
        self.detail_font_combo.grid(row=0, column=8)
        self.detail_font_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self.on_detail_font_changed()
        )
        ttk.Label(detail_header, text="크기").grid(row=0, column=9, padx=(8, 2))
        detail_font_size_spin = ttk.Spinbox(
            detail_header,
            from_=7,
            to=32,
            increment=1,
            textvariable=self.detail_font_size_var,
            width=4,
            command=self.on_detail_font_changed,
        )
        detail_font_size_spin.grid(row=0, column=10)
        detail_font_size_spin.bind(
            "<FocusOut>", lambda _event: self.on_detail_font_changed()
        )
        detail_font_size_spin.bind(
            "<Return>", lambda _event: self.on_detail_font_changed()
        )
        ttk.Button(
            detail_header, text="북마크", command=self.toggle_selected_bookmarks
        ).grid(row=0, column=11, padx=(8, 0))
        ttk.Button(detail_header, text="메모", command=self.edit_selected_memo).grid(
            row=0, column=12, padx=(6, 0)
        )
        ttk.Button(
            detail_header, text="로그 보기 전용", command=self.activate_log_view_layout
        ).grid(row=0, column=13, padx=(12, 0))
        ttk.Button(
            detail_header, text="기본 레이아웃", command=self.restore_default_layout
        ).grid(row=0, column=14, padx=(6, 0))
        self.detail_pane_container = ttk.Frame(self.detail_frame)
        self.detail_pane_container.grid(row=2, column=0, sticky="nsew")
        self.detail_pane_container.columnconfigure(0, weight=1)
        self.detail_pane_container.rowconfigure(0, weight=1)
        self.detail_pane = ttk.PanedWindow(
            self.detail_pane_container,
            orient="vertical",
        )
        self.detail_pane.grid(row=0, column=0, sticky="nsew")
        self.content_pane.add(self.detail_frame, weight=1)

        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=6, column=0, sticky="ew")
        status_frame.columnconfigure(0, weight=1)
        status = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w",
            padding=(8, 4),
        )
        status.grid(row=0, column=0, sticky="ew")
        self.progress = ttk.Progressbar(
            status_frame,
            mode="determinate",
            length=220,
            maximum=100,
        )
        self.progress.grid(row=0, column=1, sticky="e", padx=(8, 10))
        ttk.Label(
            status_frame,
            textvariable=self.progress_percent_var,
            width=5,
            anchor="e",
        ).grid(row=0, column=2, sticky="e", padx=(0, 10))
        self._setup_drag_and_drop()
        self.apply_theme(save=False)

    def _load_settings(self) -> dict:
        try:
            if APP_CONFIG_PATH.exists():
                data = json.loads(APP_CONFIG_PATH.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            return {}
        return {}

    def _load_search_presets(self) -> dict[str, dict]:
        presets = self.settings.get("search_presets", {})
        return presets if isinstance(presets, dict) else {}

    def _load_bookmarks(self) -> dict[str, str]:
        bookmarks = self.settings.get("bookmarks", {})
        if not isinstance(bookmarks, dict):
            return {}
        return {str(key): str(value) for key, value in bookmarks.items()}

    def _load_exclude_ceid_items(self) -> list[dict]:
        items = self.settings.get("exclude_s6f11_ceid_items")
        parsed: list[dict] = []
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                try:
                    start = int(item.get("start"))
                    end = int(item.get("end", start))
                except (TypeError, ValueError):
                    continue
                if start > end:
                    start, end = end, start
                parsed.append(
                    {
                        "enabled": bool(item.get("enabled", True)),
                        "start": start,
                        "end": end,
                        "name": str(item.get("name", "")).strip(),
                        "memo": str(item.get("memo", "")).strip(),
                    }
                )
        if parsed:
            return parsed

        text = str(self.settings.get("exclude_s6f11_ceid_ranges", "411001-411604"))
        try:
            return [
                {
                    "enabled": True,
                    "start": start,
                    "end": end,
                    "name": "",
                    "memo": "기존 설정",
                }
                for start, end in self._parse_ceid_range_text(text)
            ]
        except ValueError:
            return []

    def _parse_ceid_range_text(self, text: str) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for part in text.replace(";", ",").split(","):
            token = part.strip()
            if not token:
                continue
            if "-" in token:
                start_text, end_text = token.split("-", 1)
                start = int(start_text.strip())
                end = int(end_text.strip())
            else:
                start = end = int(token)
            if start > end:
                raise ValueError(f"잘못된 CEID 범위입니다: {token}")
            ranges.append((start, end))
        return ranges

    def _exclude_ceid_legacy_text(self) -> str:
        parts = []
        for item in self.exclude_ceid_items:
            start = int(item["start"])
            end = int(item["end"])
            parts.append(str(start) if start == end else f"{start}-{end}")
        return ", ".join(parts)

    def _exclude_ceid_summary(self) -> str:
        enabled = [item for item in self.exclude_ceid_items if item.get("enabled", True)]
        if not enabled:
            return "제외 CEID 없음"
        singles = sum(1 for item in enabled if int(item["start"]) == int(item["end"]))
        ranges = len(enabled) - singles
        parts = []
        if singles:
            parts.append(f"단일 {singles}개")
        if ranges:
            parts.append(f"범위 {ranges}개")
        return " / ".join(parts)

    def _load_visible_columns(self) -> list[str]:
        visibility = self.settings.get("column_visibility")
        if isinstance(visibility, dict):
            visible = [
                column
                for column in COLUMNS
                if bool(visibility.get(column, True))
            ]
            return visible or ["message"]

        visible_columns = self.settings.get("visible_columns")
        if not isinstance(visible_columns, list):
            return list(COLUMNS)

        visible = [column for column in visible_columns if column in COLUMNS]
        # Bookmark/memo are newer columns; show them by default during migration.
        for new_column in reversed(("bookmark", "memo")):
            if new_column not in visible:
                visible.insert(0, new_column)
        return visible or ["message"]

    def _save_settings(self) -> None:
        self.settings["visible_columns"] = self.visible_columns
        self.settings["column_visibility"] = {
            column: column in self.visible_columns for column in COLUMNS
        }
        self.settings["exclude_s6f11_enabled"] = self.exclude_s6f11_var.get()
        self.settings["exclude_s6f11_ceid_items"] = self.exclude_ceid_items
        self.settings["exclude_s6f11_ceid_ranges"] = self._exclude_ceid_legacy_text()
        self.settings["search_presets"] = self.search_presets
        self.settings["bookmarks"] = self.bookmarks
        self.settings["context_rows"] = self.context_rows_var.get()
        self.settings["theme"] = self.theme_var.get()
        self.settings["detail_header_enabled"] = self.detail_header_var.get()
        self.settings["compare_mode_enabled"] = self.compare_mode_var.get()
        self.settings["detail_font_family"] = self.detail_font_family_var.get()
        self.settings["detail_font_size"] = self._detail_font_size()
        self.settings["db_annotation_enabled"] = self.db_annotation_var.get()
        self.settings["db_server"] = self.db_server_var.get().strip() or DEFAULT_SERVER
        self.settings["db_database"] = self.db_database_var.get().strip() or DEFAULT_DATABASE
        self.settings["db_driver"] = self.db_driver_var.get().strip() or DEFAULT_DRIVER
        self.settings["db_database_values"] = self.db_database_values
        selected_sxfy_filters = self._selected_sxfy_filters_for_save()
        if selected_sxfy_filters is not None:
            self.settings["sxfy_selected_filters"] = selected_sxfy_filters
        APP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        APP_CONFIG_PATH.write_text(
            json.dumps(self.settings, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def save_s6f11_exclude_settings(self) -> None:
        self.exclude_ceid_var.set(self._exclude_ceid_legacy_text())
        self.exclude_ceid_summary_var.set(self._exclude_ceid_summary())
        self._save_settings()
        self.status_var.set(f"S6F11 제외 설정 저장됨: {APP_CONFIG_PATH}")

    def save_db_settings(self) -> None:
        database = self.db_database_var.get().strip()
        if database and database not in self.db_database_values:
            self.db_database_values.insert(0, database)
            if hasattr(self, "db_database_combo"):
                self.db_database_combo.configure(values=self.db_database_values)
        self._save_settings()
        self.status_var.set(f"DB 설정 저장됨: {APP_CONFIG_PATH}")

    def load_database_list(self) -> None:
        server = self.db_server_var.get().strip() or DEFAULT_SERVER
        driver = self.db_driver_var.get().strip() or DEFAULT_DRIVER
        self.save_db_settings()
        self.status_var.set("DB 목록 조회 중...")
        self._set_controls_busy(True)

        def worker() -> None:
            try:
                names = load_database_names(server=server, driver=driver)
            except Exception as exc:
                self.root.after(0, lambda: self._database_list_failed(str(exc)))
                return
            self.root.after(0, lambda: self._database_list_loaded(names))

        threading.Thread(target=worker, daemon=True).start()

    def _database_list_loaded(self, names: list[str]) -> None:
        self._set_controls_busy(False)
        current = self.db_database_var.get().strip()
        self.db_database_values = list(names)
        if current and current not in self.db_database_values:
            self.db_database_values.insert(0, current)
        self.db_database_combo.configure(values=self.db_database_values)
        if not current and names:
            self.db_database_var.set(names[0])
        self._save_settings()
        self.status_var.set(f"DB 목록 {len(names)}개를 불러왔습니다.")

    def _database_list_failed(self, error: str) -> None:
        self._set_controls_busy(False)
        self.status_var.set(f"DB 목록 조회 실패: {error}")
        messagebox.showerror("DB 목록 조회 실패", error)

    def open_ceid_exclude_editor(self) -> None:
        window = Toplevel(self.root)
        window.title("S6F11 제외 CEID 편집")
        screen_width = max(1024, window.winfo_screenwidth())
        screen_height = max(768, window.winfo_screenheight())
        width = min(1380, screen_width - 40)
        height = min(720, screen_height - 80)
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
        window.minsize(min(1280, width), min(680, height))
        window.transient(self.root)
        window.grab_set()
        window.columnconfigure(0, weight=1)
        window.rowconfigure(1, weight=1)

        items = [dict(item) for item in self.exclude_ceid_items]
        enabled_var = BooleanVar(value=True)
        start_var = StringVar()
        end_var = StringVar()
        name_var = StringVar()
        memo_var = StringVar()
        search_var = StringVar()
        editor_status_var = StringVar(
            value="Events 테이블에서 CEID 또는 이름을 검색해서 제외 목록에 추가할 수 있습니다."
        )

        form = ttk.Frame(window, padding=(10, 10, 10, 4))
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(9, weight=1)
        ttk.Checkbutton(form, text="사용", variable=enabled_var).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Label(form, text="시작 CEID").grid(row=0, column=1, padx=(0, 4))
        ttk.Entry(form, textvariable=start_var, width=10).grid(
            row=0, column=2, padx=(0, 8)
        )
        ttk.Label(form, text="끝 CEID").grid(row=0, column=3, padx=(0, 4))
        ttk.Entry(form, textvariable=end_var, width=10).grid(
            row=0, column=4, padx=(0, 8)
        )
        ttk.Label(form, text="이름").grid(row=0, column=5, padx=(0, 4))
        ttk.Entry(form, textvariable=name_var, width=24).grid(
            row=0, column=6, padx=(0, 8)
        )
        ttk.Label(form, text="메모").grid(row=0, column=7, padx=(0, 4))
        ttk.Entry(form, textvariable=memo_var, width=24).grid(
            row=0, column=8, padx=(0, 8), sticky="ew"
        )

        body = ttk.PanedWindow(window, orient="horizontal")
        body.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 8))

        list_frame = ttk.Frame(body)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        columns = ("enabled", "start", "end", "name", "memo")
        exclude_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="extended",
        )
        for column, label, width in (
            ("enabled", "사용", 60),
            ("start", "시작 CEID", 90),
            ("end", "끝 CEID", 90),
            ("name", "Name", 220),
            ("memo", "메모", 220),
        ):
            exclude_tree.heading(column, text=label)
            exclude_tree.column(column, width=width, anchor="w")
        exclude_scroll = ttk.Scrollbar(
            list_frame, orient="vertical", command=exclude_tree.yview
        )
        exclude_tree.configure(yscrollcommand=exclude_scroll.set)
        exclude_tree.grid(row=0, column=0, sticky="nsew")
        exclude_scroll.grid(row=0, column=1, sticky="ns")
        body.add(list_frame, weight=3)

        search_frame = ttk.Frame(body)
        search_frame.columnconfigure(0, weight=1)
        search_frame.rowconfigure(2, weight=1)
        ttk.Label(search_frame, text="Events 검색").grid(row=0, column=0, sticky="w")
        search_entry = ttk.Entry(search_frame, textvariable=search_var)
        search_entry.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        result_tree = ttk.Treeview(
            search_frame,
            columns=("ceid", "name"),
            show="headings",
            selectmode="extended",
        )
        result_tree.heading("ceid", text="CEID")
        result_tree.heading("name", text="Name")
        result_tree.column("ceid", width=90, anchor="w")
        result_tree.column("name", width=260, anchor="w")
        result_scroll = ttk.Scrollbar(
            search_frame, orient="vertical", command=result_tree.yview
        )
        result_tree.configure(yscrollcommand=result_scroll.set)
        result_tree.grid(row=2, column=0, sticky="nsew")
        result_scroll.grid(row=2, column=1, sticky="ns")
        body.add(search_frame, weight=2)

        def refresh_items() -> None:
            exclude_tree.delete(*exclude_tree.get_children())
            for index, item in enumerate(items):
                exclude_tree.insert(
                    "",
                    "end",
                    iid=str(index),
                    values=(
                        "Y" if item.get("enabled", True) else "N",
                        item["start"],
                        item["end"],
                        item.get("name", ""),
                        item.get("memo", ""),
                    ),
                )

        def selected_item_indices() -> list[int]:
            selected = exclude_tree.selection()
            return sorted(int(item) for item in selected)

        def load_selected_item(_event=None) -> None:
            indices = selected_item_indices()
            if len(indices) != 1:
                return
            index = indices[0]
            item = items[index]
            enabled_var.set(bool(item.get("enabled", True)))
            start_var.set(str(item["start"]))
            end_var.set(str(item["end"]))
            name_var.set(str(item.get("name", "")))
            memo_var.set(str(item.get("memo", "")))

        def read_form_item() -> dict | None:
            try:
                start = int(start_var.get().strip())
                end_text = end_var.get().strip()
                end = int(end_text) if end_text else start
            except ValueError:
                messagebox.showerror("CEID 입력 오류", "CEID는 숫자로 입력하세요.", parent=window)
                return None
            if start > end:
                messagebox.showerror(
                    "CEID 입력 오류",
                    "시작 CEID는 끝 CEID보다 클 수 없습니다.",
                    parent=window,
                )
                return None
            return {
                "enabled": enabled_var.get(),
                "start": start,
                "end": end,
                "name": name_var.get().strip(),
                "memo": memo_var.get().strip(),
            }

        def add_item() -> None:
            item = read_form_item()
            if item is None:
                return
            items.append(item)
            refresh_items()
            exclude_tree.selection_set(str(len(items) - 1))
            editor_status_var.set(f"CEID {item['start']} 추가됨")

        def update_item() -> None:
            indices = selected_item_indices()
            if len(indices) != 1:
                messagebox.showinfo("CEID 수정", "수정할 항목을 선택하세요.", parent=window)
                return
            index = indices[0]
            item = read_form_item()
            if item is None:
                return
            items[index] = item
            refresh_items()
            exclude_tree.selection_set(str(index))
            editor_status_var.set(f"CEID {item['start']} 수정됨")

        def toggle_item() -> None:
            indices = selected_item_indices()
            if not indices:
                return
            should_enable = any(not bool(items[index].get("enabled", True)) for index in indices)
            for index in indices:
                items[index]["enabled"] = should_enable
            refresh_items()
            for index in indices:
                exclude_tree.selection_add(str(index))
            load_selected_item()

        def delete_item() -> None:
            indices = selected_item_indices()
            if not indices:
                messagebox.showinfo("CEID 삭제", "삭제할 항목을 선택하세요.", parent=window)
                return
            for index in reversed(indices):
                del items[index]
            refresh_items()
            editor_status_var.set(f"선택 항목 {len(indices)}개 삭제됨")

        def clear_form() -> None:
            enabled_var.set(True)
            start_var.set("")
            end_var.set("")
            name_var.set("")
            memo_var.set("")
            exclude_tree.selection_remove(exclude_tree.selection())

        def run_event_search() -> None:
            term = search_var.get().strip()
            if not term:
                messagebox.showinfo("Events 검색", "검색어를 입력하세요.", parent=window)
                return
            result_tree.delete(*result_tree.get_children())
            editor_status_var.set("Events 검색 중...")
            window.update_idletasks()
            try:
                rows = search_events(
                    term,
                    server=self.db_server_var.get().strip() or DEFAULT_SERVER,
                    database=self.db_database_var.get().strip() or DEFAULT_DATABASE,
                    driver=self.db_driver_var.get().strip() or DEFAULT_DRIVER,
                )
            except Exception as exc:
                editor_status_var.set(f"Events 검색 실패: {exc}")
                messagebox.showerror("Events 검색 실패", str(exc), parent=window)
                return
            for index, (ceid, name) in enumerate(rows):
                result_tree.insert("", "end", iid=str(index), values=(ceid, name))
            editor_status_var.set(f"Events 검색 결과 {len(rows)}건")

        def add_selected_event() -> None:
            selected = result_tree.selection()
            if not selected:
                messagebox.showinfo("Events 추가", "추가할 검색 결과를 선택하세요.", parent=window)
                return
            added = 0
            for item_id in selected:
                ceid_text, name = result_tree.item(item_id, "values")
                ceid = int(ceid_text)
                items.append(
                    {
                        "enabled": True,
                        "start": ceid,
                        "end": ceid,
                        "name": str(name),
                        "memo": "Events 검색",
                    }
                )
                added += 1
            refresh_items()
            editor_status_var.set(f"Events 검색 결과 {added}개 추가됨")

        def save_and_close() -> None:
            self.exclude_ceid_items = [dict(item) for item in items]
            self.save_s6f11_exclude_settings()
            window.destroy()

        exclude_tree.bind("<<TreeviewSelect>>", load_selected_item)
        exclude_tree.bind("<Double-1>", lambda _event: toggle_item())
        search_entry.bind("<Return>", lambda _event: run_event_search())
        result_tree.bind("<Double-1>", lambda _event: add_selected_event())

        command_frame = ttk.Frame(window, padding=(10, 0, 10, 8))
        command_frame.grid(row=2, column=0, sticky="ew")
        command_frame.columnconfigure(7, weight=1)
        ttk.Button(command_frame, text="추가", command=add_item).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(command_frame, text="수정", command=update_item).grid(
            row=0, column=1, padx=(0, 6)
        )
        ttk.Button(command_frame, text="사용 전환", command=toggle_item).grid(
            row=0, column=2, padx=(0, 6)
        )
        ttk.Button(command_frame, text="삭제", command=delete_item).grid(
            row=0, column=3, padx=(0, 14)
        )
        ttk.Button(command_frame, text="입력 비우기", command=clear_form).grid(
            row=0, column=4, padx=(0, 14)
        )
        ttk.Button(command_frame, text="Events 검색", command=run_event_search).grid(
            row=0, column=5, padx=(0, 6)
        )
        ttk.Button(command_frame, text="검색 결과 추가", command=add_selected_event).grid(
            row=0, column=6, padx=(0, 14)
        )
        ttk.Label(command_frame, textvariable=editor_status_var).grid(
            row=0, column=7, sticky="w"
        )
        ttk.Button(command_frame, text="저장", command=save_and_close).grid(
            row=0, column=10, padx=(8, 6)
        )
        ttk.Button(command_frame, text="취소", command=window.destroy).grid(
            row=0, column=11
        )

        refresh_items()
        search_entry.focus_set()

    def on_theme_changed(self) -> None:
        if not hasattr(self, "root"):
            return
        self.apply_theme(save=True)

    def apply_theme(self, save: bool = True) -> None:
        theme_name = self.theme_var.get()
        colors = THEMES.get(theme_name, THEMES["light"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.root.configure(bg=colors["bg"])
        self.root.option_add("*Menu.background", colors["panel"])
        self.root.option_add("*Menu.foreground", colors["text"])
        self.root.option_add("*Menu.activeBackground", colors["select_bg"])
        self.root.option_add("*Menu.activeForeground", colors["select_fg"])

        style.configure(".", background=colors["bg"], foreground=colors["text"])
        style.configure("TFrame", background=colors["bg"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["text"])
        style.configure("TButton", background=colors["panel"], foreground=colors["text"])
        style.map("TButton", background=[("active", colors["select_bg"])])
        style.configure("TCheckbutton", background=colors["bg"], foreground=colors["text"])
        style.map("TCheckbutton", background=[("active", colors["bg"])])
        style.configure("TMenubutton", background=colors["panel"], foreground=colors["text"])
        style.configure("TEntry", fieldbackground=colors["field"], foreground=colors["text"])
        style.configure("TCombobox", fieldbackground=colors["field"], foreground=colors["text"])
        style.configure("TSpinbox", fieldbackground=colors["field"], foreground=colors["text"])
        style.configure(
            "Treeview",
            background=colors["tree_bg"],
            fieldbackground=colors["tree_bg"],
            foreground=colors["text"],
            bordercolor=colors["border"],
        )
        style.configure(
            "Treeview.Heading",
            background=colors["panel"],
            foreground=colors["text"],
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", colors["select_bg"])],
            foreground=[("selected", colors["select_fg"])],
        )
        style.configure(
            "TProgressbar",
            background=colors["accent"],
            troughcolor=colors["field"],
            bordercolor=colors["border"],
        )

        for text_name in ("keyword_tag_text", "exclude_keyword_tag_text"):
            if hasattr(self, text_name):
                text = getattr(self, text_name)
                text.configure(
                    bg=colors["field"],
                    fg=colors["text"],
                    selectbackground=colors["select_bg"],
                    selectforeground=colors["select_fg"],
                    highlightbackground=colors["border"],
                    insertbackground=colors["text"],
                )
        for menu_name in ("column_menu", "preset_menu", "sxfy_menu"):
            if hasattr(self, menu_name):
                menu = getattr(self, menu_name)
                menu.configure(
                    bg=colors["panel"],
                    fg=colors["text"],
                    activebackground=colors["select_bg"],
                    activeforeground=colors["select_fg"],
                )
        if hasattr(self, "tree"):
            self.tree.tag_configure("bookmarked", background=colors["tree_alt"])
        if hasattr(self, "splitter_grip"):
            self.splitter_grip.configure(background=colors["grip_bg"])
            self._draw_splitter_grip()
        if hasattr(self, "keyword_tag_text"):
            self._refresh_keyword_listboxes()
        if save:
            self._save_settings()

    def _build_column_menu(self) -> None:
        self.column_menu.delete(0, "end")
        for column in COLUMNS:
            self.column_menu.add_checkbutton(
                label=COLUMN_LABELS[column],
                variable=self.column_visible_vars[column],
                command=self._on_column_visibility_changed,
            )
        self.column_menu.add_separator()
        self.column_menu.add_command(label="전체 표시", command=self.show_all_columns)

    def _build_preset_menu(self) -> None:
        self.preset_menu.delete(0, "end")
        if not self.search_presets:
            self.preset_menu.add_command(label="저장된 프리셋 없음", state="disabled")
            return
        for name in sorted(self.search_presets):
            self.preset_menu.add_command(
                label=name,
                command=lambda preset_name=name: self.load_search_preset(preset_name),
            )

    def _build_sxfy_menu(self) -> None:
        self.sxfy_menu.delete(0, "end")
        if not self.sxfy_types:
            self.sxfy_menu.add_command(label="분석 후 사용 가능", state="disabled")
            return
        self.sxfy_menu.add_command(label="전체 선택", command=self.select_all_sxfy_filters)
        self.sxfy_menu.add_command(label="전체 해제", command=self.clear_all_sxfy_filters)
        self.sxfy_menu.add_separator()
        for message_type in self.sxfy_types:
            self.sxfy_menu.add_checkbutton(
                label=message_type,
                variable=self.sxfy_filter_vars[message_type],
                command=self.on_sxfy_filter_changed,
            )

    def _update_sxfy_filters(self, entries: list[LogEntry]) -> None:
        previous = {
            message_type: variable.get()
            for message_type, variable in self.sxfy_filter_vars.items()
        }
        types = sorted(
            {
                _sxfy_label(match)
                for entry in entries
                for match in SXFy_RE.finditer(entry.message)
            }
        )
        saved_selected = self.settings.get("sxfy_selected_filters")
        saved_selected_set = (
            {str(message_type).upper() for message_type in saved_selected}
            if isinstance(saved_selected, list)
            else None
        )
        self.sxfy_types = types
        self.sxfy_filter_vars = {
            message_type: BooleanVar(
                value=(
                    message_type in saved_selected_set
                    if saved_selected_set is not None
                    else previous.get(message_type, True)
                )
            )
            for message_type in self.sxfy_types
        }
        self._build_sxfy_menu()

    def _selected_sxfy_filters_for_save(self) -> list[str] | None:
        if not self.sxfy_filter_vars:
            saved = self.settings.get("sxfy_selected_filters")
            return saved if isinstance(saved, list) else None
        return [
            message_type
            for message_type in self.sxfy_types
            if self.sxfy_filter_vars[message_type].get()
        ]

    def on_sxfy_filter_changed(self) -> None:
        self._save_settings()
        self.apply_filters()

    def select_all_sxfy_filters(self) -> None:
        for variable in self.sxfy_filter_vars.values():
            variable.set(True)
        self._save_settings()
        self.apply_filters()

    def clear_all_sxfy_filters(self) -> None:
        for variable in self.sxfy_filter_vars.values():
            variable.set(False)
        self._save_settings()
        self.apply_filters()

    def _on_column_visibility_changed(self) -> None:
        selected = [
            column
            for column in COLUMNS
            if self.column_visible_vars[column].get()
        ]
        if not selected:
            self.column_visible_vars["message"].set(True)
            selected = ["message"]
            messagebox.showinfo("컬럼 설정", "최소 1개 컬럼은 표시되어야 합니다.")
        self.visible_columns = selected
        self._apply_visible_columns(save=True)

    def _apply_visible_columns(self, save: bool = True) -> None:
        if not hasattr(self, "tree"):
            return
        self.tree.configure(displaycolumns=self.visible_columns)
        if save:
            self._save_settings()
            self.status_var.set(f"컬럼 설정 저장됨: {APP_CONFIG_PATH}")
            self.show_selected_detail()

    def show_all_columns(self) -> None:
        for variable in self.column_visible_vars.values():
            variable.set(True)
        self.visible_columns = list(COLUMNS)
        self._apply_visible_columns(save=True)

    def _draw_splitter_grip(self, event=None) -> None:
        colors = THEMES.get(self.theme_var.get(), THEMES["light"])
        canvas = self.splitter_grip
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        canvas.delete("all")
        center_y = height // 2
        canvas.create_line(0, center_y, width, center_y, fill=colors["grip_line"], width=1)
        start_x = max(0, width // 2 - 28)
        for offset in range(0, 57, 8):
            canvas.create_oval(
                start_x + offset,
                center_y - 2,
                start_x + offset + 4,
                center_y + 2,
                fill=colors["grip_dot"],
                outline="",
            )

    def _drag_main_splitter(self, event) -> str:
        if self.log_view_layout_active:
            return "break"
        y = event.y_root - self.content_pane.winfo_rooty()
        min_y = 120
        max_y = max(min_y, self.content_pane.winfo_height() - 120)
        self.content_pane.sashpos(0, max(min_y, min(y, max_y)))
        return "break"

    def activate_log_view_layout(self) -> None:
        if self.log_view_layout_active:
            return
        panes = tuple(str(pane) for pane in self.content_pane.panes())
        if str(self.table_frame) in panes:
            self.content_pane.forget(self.table_frame)
        for frame in self._top_control_frames():
            frame.grid_remove()
        self.content_pane.grid_configure(row=0, rowspan=6, padx=10, pady=(0, 8))
        for row in range(0, 5):
            self.root.rowconfigure(row, weight=0)
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(5, weight=0)
        self.log_view_layout_active = True
        self.status_var.set("로그 보기 전용 레이아웃으로 전환했습니다.")

    def restore_default_layout(self) -> None:
        self.content_pane.grid_configure(row=5, rowspan=1, padx=10, pady=(0, 8))
        for row in range(0, 5):
            self.root.rowconfigure(row, weight=0)
        self.root.rowconfigure(5, weight=1)
        for frame in self._top_control_frames():
            frame.grid()
        panes = tuple(str(pane) for pane in self.content_pane.panes())
        if str(self.table_frame) not in panes:
            self.content_pane.insert(0, self.table_frame, weight=4)
        if str(self.detail_frame) not in tuple(str(pane) for pane in self.content_pane.panes()):
            self.content_pane.add(self.detail_frame, weight=1)
        self.log_view_layout_active = False
        self.status_var.set("기본 레이아웃으로 복귀했습니다.")

    def _top_control_frames(self) -> tuple[ttk.Frame, ...]:
        return (
            self.toolbar_frame,
            self.actions_frame,
            self.db_frame,
            self.keyword_panel,
            self.drop_frame,
        )

    def _entry_key(self, entry: LogEntry) -> str:
        return f"{entry.source_file}|{entry.line_no}|{entry.display_time}"

    def _entry_memo(self, entry: LogEntry) -> str:
        return self.bookmarks.get(self._entry_key(entry), "")

    def _is_bookmarked(self, entry: LogEntry) -> bool:
        return self._entry_key(entry) in self.bookmarks

    def _selected_display_indices(self) -> list[int]:
        return sorted(
            int(item)
            for item in self.tree.selection()
            if item.isdigit() and int(item) < len(self.filtered_entries)
        )

    def _active_sxfy_filter_set(self) -> set[str] | None:
        if not self.sxfy_types:
            return None
        selected = {
            message_type
            for message_type, variable in self.sxfy_filter_vars.items()
            if variable.get()
        }
        if selected == set(self.sxfy_types):
            return None
        return selected

    def _entry_sxfy_type(self, entry: LogEntry) -> str | None:
        match = SXFy_RE.search(entry.message)
        return _sxfy_label(match) if match else None

    def on_context_rows_changed(self) -> None:
        self._save_settings()
        self.show_selected_detail()

    def on_detail_header_changed(self) -> None:
        self._save_settings()
        self.show_selected_detail()
        state = "표시" if self.detail_header_var.get() else "숨김"
        self.status_var.set(f"상세 로그 헤더 {state} 설정 저장됨: {APP_CONFIG_PATH}")

    def on_compare_mode_changed(self) -> None:
        self._save_settings()
        self.show_selected_detail()
        state = "사용" if self.compare_mode_var.get() else "해제"
        self.status_var.set(f"로그 비교 보기 {state} 설정 저장됨: {APP_CONFIG_PATH}")

    def _detail_font_size(self) -> int:
        try:
            size = int(self.detail_font_size_var.get())
        except Exception:
            size = 10
        size = max(7, min(32, size))
        try:
            current_size = int(self.detail_font_size_var.get())
        except Exception:
            current_size = None
        if current_size != size:
            self.detail_font_size_var.set(size)
        return size

    def _detail_font(self) -> tuple[str, int]:
        family = self.detail_font_family_var.get().strip() or "Consolas"
        if family not in DETAIL_FONT_VALUES:
            family = "Consolas"
            self.detail_font_family_var.set(family)
        return family, self._detail_font_size()

    def on_detail_font_changed(self) -> None:
        self._detail_font()
        self._save_settings()
        self.show_selected_detail()
        self.status_var.set(f"상세 로그 폰트 설정 저장됨: {APP_CONFIG_PATH}")

    def toggle_selected_bookmarks(self) -> None:
        indices = self._selected_display_indices()
        if not indices:
            messagebox.showinfo("북마크", "북마크할 로그를 선택하세요.")
            return
        should_add = any(not self._is_bookmarked(self.filtered_entries[index]) for index in indices)
        for index in indices:
            entry = self.filtered_entries[index]
            key = self._entry_key(entry)
            if should_add:
                self.bookmarks.setdefault(key, "")
            else:
                self.bookmarks.pop(key, None)
        self._save_settings()
        self.refresh_table(keep_detail=True)
        for index in indices:
            if str(index) in self.tree.get_children():
                self.tree.selection_add(str(index))
        self.show_selected_detail()

    def edit_selected_memo(self) -> None:
        indices = self._selected_display_indices()
        if not indices:
            messagebox.showinfo("메모", "메모를 작성할 로그를 선택하세요.")
            return
        entry = self.filtered_entries[indices[0]]
        key = self._entry_key(entry)
        current = self.bookmarks.get(key, "")
        memo = simpledialog.askstring("로그 메모", "메모를 입력하세요.", initialvalue=current)
        if memo is None:
            return
        memo = memo.strip()
        if memo:
            self.bookmarks[key] = memo
        else:
            self.bookmarks.pop(key, None)
        self._save_settings()
        self.refresh_table(keep_detail=True)
        self.tree.selection_set(str(indices[0]))
        self.show_selected_detail()

    def _highlight_terms(self) -> list[str]:
        return [keyword for _mode, keyword in self.keywords if keyword.strip()]

    def _refresh_keyword_listboxes(self) -> None:
        self._render_keyword_tags()
        self._render_exclude_keyword_tags()

    def _render_keyword_tags(self) -> None:
        self._render_tag_text(
            self.keyword_tag_text,
            [
                (
                    self._keyword_label(mode, keyword),
                    index,
                    self.selected_keyword_index == index,
                    lambda _event, i=index: self.select_keyword_tag(i),
                )
                for index, (mode, keyword) in enumerate(self.keywords)
            ],
        )

    def _render_exclude_keyword_tags(self) -> None:
        self._render_tag_text(
            self.exclude_keyword_tag_text,
            [
                (
                    keyword,
                    index,
                    self.selected_exclude_keyword_index == index,
                    lambda _event, i=index: self.select_exclude_keyword_tag(i),
                )
                for index, keyword in enumerate(self.exclude_keywords)
            ],
        )

    def _render_tag_text(self, widget: Text, chips: list[tuple[str, int, bool, object]]) -> None:
        colors = THEMES.get(self.theme_var.get(), THEMES["light"])
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for tag_name in widget.tag_names():
            if tag_name.startswith("chip_"):
                widget.tag_delete(tag_name)
        for label, index, selected, callback in chips:
            tag_name = f"chip_{index}"
            chip_text = f" {label} "
            start = widget.index("end-1c")
            widget.insert("end", chip_text)
            end = widget.index("end-1c")
            widget.tag_add(tag_name, start, end)
            widget.tag_configure(
                tag_name,
                background=colors["select_bg"] if selected else colors["panel"],
                foreground=colors["select_fg"] if selected else colors["text"],
                relief="raised",
                borderwidth=1,
            )
            widget.tag_bind(tag_name, "<Button-1>", callback)
            widget.insert("end", " ")
        widget.configure(state="disabled")

    def select_keyword_tag(self, index: int) -> str:
        if index >= len(self.keywords):
            return "break"
        self.selected_keyword_index = index
        mode, keyword = self.keywords[index]
        self.keyword_mode_var.set(mode)
        self.keyword_var.set(keyword)
        self._render_keyword_tags()
        self.keyword_tag_text.focus_set()
        return "break"

    def select_exclude_keyword_tag(self, index: int) -> str:
        if index >= len(self.exclude_keywords):
            return "break"
        self.selected_exclude_keyword_index = index
        self.exclude_keyword_var.set(self.exclude_keywords[index])
        self._render_exclude_keyword_tags()
        self.exclude_keyword_tag_text.focus_set()
        return "break"

    def _current_search_preset(self) -> dict:
        return {
            "keywords": [
                {"mode": mode, "keyword": keyword}
                for mode, keyword in self.keywords
            ],
            "exclude_keywords": list(self.exclude_keywords),
            "case_sensitive": self.case_sensitive_var.get(),
            "use_regex": self.regex_search_var.get(),
        }

    def save_search_preset(self) -> None:
        name = self.preset_name_var.get().strip()
        if not name:
            messagebox.showinfo("검색 프리셋", "프리셋 이름을 입력하세요.")
            return
        self.search_presets[name] = self._current_search_preset()
        self._save_settings()
        self._build_preset_menu()
        self.status_var.set(f"검색 프리셋 저장됨: {name}")

    def load_search_preset(self, name: str | None = None) -> None:
        preset_name = (name or self.preset_name_var.get()).strip()
        preset = self.search_presets.get(preset_name)
        if not preset:
            messagebox.showinfo("검색 프리셋", "불러올 프리셋을 선택하세요.")
            return

        keywords: list[tuple[str, str]] = []
        for item in preset.get("keywords", []):
            if not isinstance(item, dict):
                continue
            mode = str(item.get("mode", "AND")).upper()
            keyword = str(item.get("keyword", "")).strip()
            if mode in {"AND", "OR"} and keyword:
                keywords.append((mode, keyword))
        self.keywords = keywords
        self.exclude_keywords = [
            str(keyword).strip()
            for keyword in preset.get("exclude_keywords", [])
            if str(keyword).strip()
        ]
        self.case_sensitive_var.set(bool(preset.get("case_sensitive", False)))
        self.regex_search_var.set(bool(preset.get("use_regex", False)))
        self.preset_name_var.set(preset_name)
        self.keyword_var.set("")
        self.exclude_keyword_var.set("")
        self.selected_keyword_index = None
        self.selected_exclude_keyword_index = None
        self._refresh_keyword_listboxes()
        self.apply_filters()
        self.status_var.set(f"검색 프리셋 불러옴: {preset_name}")

    def delete_search_preset(self) -> None:
        name = self.preset_name_var.get().strip()
        if not name or name not in self.search_presets:
            messagebox.showinfo("검색 프리셋", "삭제할 프리셋을 선택하거나 이름을 입력하세요.")
            return
        if not messagebox.askyesno("검색 프리셋 삭제", f"'{name}' 프리셋을 삭제할까요?"):
            return
        del self.search_presets[name]
        self.preset_name_var.set("")
        self._save_settings()
        self._build_preset_menu()
        self.status_var.set(f"검색 프리셋 삭제됨: {name}")

    def choose_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="MMI / SECS 로그 파일 선택",
            filetypes=(
                ("Log files", "*.log *.txt"),
                ("All files", "*.*"),
            ),
        )
        if not paths:
            return
        self._add_paths(paths)

    def _setup_drag_and_drop(self) -> None:
        if TkinterDnD is None or DND_FILES is None:
            return
        for widget in (self.root, self.drop_label, self.tree):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self._handle_drop)

    def _handle_drop(self, event) -> str:
        dropped_paths = self.root.tk.splitlist(event.data)
        self._add_paths(dropped_paths)
        return "break"

    def _add_paths(self, paths) -> None:
        added = 0
        for raw_path in paths:
            path = str(raw_path).strip()
            if not path:
                continue
            p = Path(path)
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".log", ".txt"}:
                continue
            normalized = str(p)
            if normalized not in self.paths:
                self.paths.append(normalized)
                added += 1

        if added:
            self.status_var.set(
                f"{added}개 파일 추가됨. 총 {len(self.paths)}개 파일 선택됨. 분석 버튼을 누르세요."
            )
        elif self.paths:
            self.status_var.set(f"총 {len(self.paths)}개 파일 선택됨. 분석 버튼을 누르세요.")
        else:
            self.status_var.set("추가된 로그 파일이 없습니다. .log 또는 .txt 파일을 선택하세요.")
        self.summary_var.set(", ".join(Path(path).name for path in self.paths[:4]))

    def add_keyword(self) -> None:
        keyword = self.keyword_var.get().strip()
        if not keyword:
            return
        mode = self.keyword_mode_var.get().strip().upper()
        if mode not in {"AND", "OR"}:
            mode = "AND"
        if self.selected_keyword_index is not None:
            index = self.selected_keyword_index
            self.keywords[index] = (mode, keyword)
            self.selected_keyword_index = None
        elif (mode, keyword) not in self.keywords:
            self.keywords.append((mode, keyword))
        self.keyword_var.set("")
        self._render_keyword_tags()
        self.apply_filters()

    def load_selected_keyword(self, _event=None) -> None:
        if self.selected_keyword_index is None:
            return
        mode, keyword = self.keywords[self.selected_keyword_index]
        self.keyword_mode_var.set(mode)
        self.keyword_var.set(keyword)

    def remove_selected_keyword(self, _event=None) -> str | None:
        if self.selected_keyword_index is None:
            return None
        del self.keywords[self.selected_keyword_index]
        self.selected_keyword_index = None
        self.keyword_var.set("")
        self._render_keyword_tags()
        self.apply_filters()
        return "break"

    def clear_keywords(self) -> None:
        self.keywords.clear()
        self.selected_keyword_index = None
        self.keyword_var.set("")
        self._render_keyword_tags()
        self.apply_filters()

    def _keyword_label(self, mode: str, keyword: str) -> str:
        return f"[{mode}] {keyword}"

    def add_exclude_keyword(self) -> None:
        keyword = self.exclude_keyword_var.get().strip()
        if not keyword:
            return
        if self.selected_exclude_keyword_index is not None:
            index = self.selected_exclude_keyword_index
            self.exclude_keywords[index] = keyword
            self.selected_exclude_keyword_index = None
        elif keyword not in self.exclude_keywords:
            self.exclude_keywords.append(keyword)
        self.exclude_keyword_var.set("")
        self._render_exclude_keyword_tags()
        self.apply_filters()

    def load_selected_exclude_keyword(self, _event=None) -> None:
        if self.selected_exclude_keyword_index is None:
            return
        self.exclude_keyword_var.set(
            self.exclude_keywords[self.selected_exclude_keyword_index]
        )

    def remove_selected_exclude_keyword(self, _event=None) -> str | None:
        if self.selected_exclude_keyword_index is None:
            return None
        del self.exclude_keywords[self.selected_exclude_keyword_index]
        self.selected_exclude_keyword_index = None
        self.exclude_keyword_var.set("")
        self._render_exclude_keyword_tags()
        self.apply_filters()
        return "break"

    def clear_exclude_keywords(self) -> None:
        self.exclude_keywords.clear()
        self.selected_exclude_keyword_index = None
        self.exclude_keyword_var.set("")
        self._render_exclude_keyword_tags()
        self.apply_filters()

    def analyze(self) -> None:
        if not self.paths:
            messagebox.showinfo("파일 선택", "먼저 로그 파일을 선택하세요.")
            return
        try:
            excluded_ranges = self._excluded_ceid_ranges()
        except ValueError as exc:
            messagebox.showerror("CEID 제외 범위 오류", str(exc))
            return
        self.save_s6f11_exclude_settings()
        self.save_db_settings()
        worker_count = max(1, len(self.paths))
        db_enabled = self.db_annotation_var.get()
        db_server = self.db_server_var.get().strip() or DEFAULT_SERVER
        db_database = self.db_database_var.get().strip() or DEFAULT_DATABASE
        db_driver = self.db_driver_var.get().strip() or DEFAULT_DRIVER
        skip_setup_dump = self.skip_setup_var.get()
        self.status_var.set(
            f"로그 로딩 준비 중... 파일 {len(self.paths)}개를 {worker_count}개 스레드로 파싱합니다."
        )
        self.progress.configure(mode="determinate", maximum=100, value=0)
        self.progress_percent_var.set("0%")
        self._set_controls_busy(True)
        worker = threading.Thread(
            target=self._analyze_worker,
            args=(
                excluded_ranges,
                worker_count,
                db_enabled,
                db_server,
                db_database,
                db_driver,
                skip_setup_dump,
            ),
            daemon=True,
        )
        worker.start()

    def _count_total_lines(self, paths: list[str]) -> int:
        total = 0
        for path in paths:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            total += count_text_lines(text)
        return total

    def _update_analysis_progress(
        self,
        analyzed_lines: int,
        total_lines: int,
        current_file: str = "",
    ) -> None:
        if total_lines <= 0:
            percent = 100
        else:
            percent = min(100, int((analyzed_lines / total_lines) * 100))
        self.progress.configure(value=percent)
        self.progress_percent_var.set(f"{percent}%")
        suffix = f" - {current_file}" if current_file else ""
        self.status_var.set(
            f"분석 라인 {analyzed_lines:,} / {total_lines:,}줄 ({percent}%){suffix}"
        )

    def _excluded_ceid_ranges(self) -> tuple[tuple[int, int], ...]:
        if not self.exclude_s6f11_var.get():
            return ()
        ranges: list[tuple[int, int]] = []
        for item in self.exclude_ceid_items:
            if not item.get("enabled", True):
                continue
            start = int(item["start"])
            end = int(item["end"])
            if start > end:
                raise ValueError(f"잘못된 CEID 범위입니다: {start}-{end}")
            ranges.append((start, end))
        return tuple(ranges)

    def _analyze_worker(
        self,
        excluded_ranges: tuple[tuple[int, int], ...],
        worker_count: int,
        db_enabled: bool,
        db_server: str,
        db_database: str,
        db_driver: str,
        skip_setup_dump: bool,
    ) -> None:
        try:
            event_names: dict[int, str] | None = None
            report_variables: dict[int, list[ReportVariable]] = {}
            mapped_count = 0
            report_variable_count = 0
            lookup_error = None
            report_variable_error = None
            if db_enabled:
                self.root.after(
                    0,
                    lambda: self.status_var.set(
                        f"DB 참조 데이터 로딩 중... {db_server} / {db_database}"
                    ),
                )
                try:
                    event_names = load_all_event_names(
                        server=db_server,
                        database=db_database,
                        driver=db_driver,
                    )
                    mapped_count = len(event_names)
                except Exception as exc:
                    event_names = {}
                    lookup_error = str(exc)
                try:
                    report_variables = load_all_report_variables(
                        server=db_server,
                        database=db_database,
                        driver=db_driver,
                    )
                    report_variable_count = sum(
                        len(items) for items in report_variables.values()
                    )
                except Exception as exc:
                    report_variables = {}
                    report_variable_error = str(exc)

            self.root.after(
                0,
                lambda: self.status_var.set("로그 라인 수 계산 중..."),
            )
            total_lines = self._count_total_lines(self.paths)
            parsed_lines = 0
            progress_lock = threading.Lock()
            self.root.after(
                0,
                lambda: self._update_analysis_progress(
                    0,
                    total_lines,
                    f"총 {total_lines:,}줄 분석 시작",
                ),
            )

            def progress_callback(filename: str, line_count: int) -> None:
                nonlocal parsed_lines
                with progress_lock:
                    parsed_lines += line_count
                    current_lines = parsed_lines
                self.root.after(
                    0,
                    lambda current=current_lines, total=total_lines, name=filename: (
                        self._update_analysis_progress(current, total, name)
                    ),
                )

            entries, skipped, file_types = parse_paths(
                self.paths,
                skip_setup_dump=skip_setup_dump,
                excluded_s6f11_ceid_ranges=excluded_ranges,
                max_workers=worker_count,
                progress_callback=progress_callback,
                event_names=event_names,
                report_variables=report_variables,
            )
            self.root.after(
                0,
                lambda: self._update_analysis_progress(
                    total_lines,
                    total_lines,
                    "파일 파싱 완료. 결과 정리 중...",
                ),
            )
            gem300_events = extract_gem300_events(entries)
            alarms = extract_alarms(entries)
            self.root.after(
                0,
                lambda: self._analysis_complete(
                    entries,
                    skipped,
                    {name: kind.value for name, kind in file_types.items()},
                    gem300_events,
                    alarms,
                    mapped_count,
                    lookup_error,
                    report_variables,
                    report_variable_count,
                    report_variable_error,
                    db_enabled,
                ),
            )
        except Exception:
            error = traceback.format_exc()
            self.root.after(0, lambda: self._analysis_failed(error))

    def _analysis_complete(
        self,
        entries: list[LogEntry],
        skipped: int,
        file_types: dict[str, str],
        gem300_events,
        alarms,
        mapped_count: int,
        lookup_error: str | None,
        report_variables: dict[int, list[ReportVariable]],
        report_variable_count: int,
        report_variable_error: str | None,
        db_enabled: bool,
    ) -> None:
        self.entries = entries
        self.skipped_setup_lines = skipped
        self.file_types = file_types
        self.gem300_events = gem300_events
        self.alarms = alarms
        self.report_variables = report_variables
        self._update_sxfy_filters(entries)
        self.progress.configure(value=100)
        self.progress_percent_var.set("100%")
        self._set_controls_busy(False)
        ceid_count = sum(1 for entry in entries if entry.ceid is not None)
        if db_enabled:
            lookup_text = (
                f" CEID 이벤트명 {mapped_count}개 사전 로드."
                if not lookup_error
                else f" 이벤트명 조회 실패: {lookup_error}"
            )
            report_variable_text = (
                f" Report VID {report_variable_count}개 사전 로드."
                if not report_variable_error
                else f" Report VID 조회 실패: {report_variable_error}"
            )
        else:
            lookup_text = " DB 주석 사용 안함."
            report_variable_text = ""
        self.status_var.set(
            f"분석 완료. 전체 {len(entries)}건, S6F11 CEID {ceid_count}건."
            f"{lookup_text}{report_variable_text}"
        )
        self.apply_filters()

    def _analysis_failed(self, error: str) -> None:
        self.progress.configure(value=0)
        self.progress_percent_var.set("")
        self._set_controls_busy(False)
        self.status_var.set("분석 실패")
        messagebox.showerror("분석 실패", error)

    def _set_controls_busy(self, busy: bool) -> None:
        cursor = "watch" if busy else ""
        self.root.configure(cursor=cursor)

    def reset_analysis(self) -> None:
        self.paths.clear()
        self.entries = []
        self.filtered_entries = []
        self.search_matches = []
        self.matched_keywords_by_entry = {}
        self.skipped_setup_lines = 0
        self.file_types = {}
        self.gem300_events = []
        self.alarms = []
        self.report_variables = {}
        self.sxfy_types = []
        self.sxfy_filter_vars = {}
        self._build_sxfy_menu()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._clear_detail()
        self.summary_var.set("")
        self.progress.configure(value=0)
        self.progress_percent_var.set("")
        self.status_var.set("분석 내용이 초기화되었습니다. 로그 파일을 다시 선택하세요.")

    def apply_filters(self) -> None:
        selected_types: set[str] = set()
        if self.filter_mmi_var.get():
            selected_types.add("MMI")
        if self.filter_secs_var.get():
            selected_types.add("SECS")

        base_entries = [
            entry for entry in self.entries if entry.log_type.value in selected_types
        ]
        sxfy_filter = self._active_sxfy_filter_set()
        if sxfy_filter is not None:
            base_entries = [
                entry
                for entry in base_entries
                if entry.log_type.value != "SECS"
                or self._entry_sxfy_type(entry) in sxfy_filter
            ]
        self.matched_keywords_by_entry = {}
        if self.keywords or self.exclude_keywords:
            and_keywords = [
                keyword for mode, keyword in self.keywords if mode == "AND"
            ]
            or_keywords = [
                keyword for mode, keyword in self.keywords if mode == "OR"
            ]
            self.search_matches = search_multiple_keywords(
                base_entries,
                and_keywords,
                or_keywords=or_keywords,
                exclude_keywords=self.exclude_keywords,
                match_all=True,
                case_sensitive=self.case_sensitive_var.get(),
                use_regex=self.regex_search_var.get(),
                log_types=selected_types,
            )
            self.filtered_entries = [match.entry for match in self.search_matches]
            self.matched_keywords_by_entry = {
                id(match.entry): match.keyword for match in self.search_matches
            }
        else:
            self.search_matches = []
            self.filtered_entries = base_entries
        self.refresh_table()

    def refresh_table(self, keep_detail: bool = False) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        rows = self.filtered_entries[: max(1, self.display_rows_var.get())]
        for index, entry in enumerate(rows):
            bookmarked = self._is_bookmarked(entry)
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=_entry_to_values(
                    entry,
                    self.matched_keywords_by_entry.get(id(entry), ""),
                    bookmarked,
                    self._entry_memo(entry),
                ),
                tags=("bookmarked",) if bookmarked else (),
            )
        hidden = max(0, len(self.filtered_entries) - len(rows))
        self.summary_var.set(
            f"표시 {len(rows)}건 / 필터 결과 {len(self.filtered_entries)}건"
            + (f" ({hidden}건 더 있음)" if hidden else "")
        )
        if not keep_detail:
            self._clear_detail()

    def show_selected_detail(self, _event=None) -> None:
        selected_indices = self._selected_display_indices()
        if not selected_indices:
            self._clear_detail()
            return
        self._clear_detail()
        if self.compare_mode_var.get() and len(selected_indices) == 2:
            self._create_compare_detail(selected_indices[0], selected_indices[1])
            return
        orient = "vertical" if self.detail_horizontal_var.get() else "horizontal"
        self.detail_pane = ttk.PanedWindow(self.detail_pane_container, orient=orient)
        self.detail_pane.grid(row=0, column=0, sticky="nsew")

        for index in selected_indices[:8]:
            entry = self.filtered_entries[index]
            pane = self._create_detail_pane(entry, index)
            self.detail_pane.add(pane, weight=1)

    def _create_compare_detail(self, left_index: int, right_index: int) -> None:
        colors = THEMES.get(self.theme_var.get(), THEMES["light"])
        container = ttk.Frame(self.detail_pane_container)
        container.grid(row=0, column=0, sticky="nsew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)
        container.rowconfigure(1, weight=0)

        compare_pane = ttk.PanedWindow(container, orient="horizontal")
        compare_pane.grid(row=0, column=0, sticky="nsew")

        left_entry = self.filtered_entries[left_index]
        right_entry = self.filtered_entries[right_index]
        left_lines = self._format_single_detail(left_entry, left_index).splitlines()
        right_lines = self._format_single_detail(right_entry, right_index).splitlines()
        left_lines, right_lines, left_marks, right_marks = self._aligned_line_diff(
            left_lines, right_lines
        )

        left_title = (
            f"#{left_index + 1}  {left_entry.display_time}  "
            f"{left_entry.source_file}:{left_entry.line_no}"
        )
        right_title = (
            f"#{right_index + 1}  {right_entry.display_time}  "
            f"{right_entry.source_file}:{right_entry.line_no}"
        )
        line_compare = self._create_line_compare_panel(container, colors)
        left_text, left_scroll = self._create_compare_side(
            compare_pane, left_title, left_lines, left_marks, colors
        )
        right_text, right_scroll = self._create_compare_side(
            compare_pane, right_title, right_lines, right_marks, colors
        )
        self._bind_compare_line_clicks(
            left_text, right_text, left_lines, right_lines, line_compare, colors
        )
        self._sync_compare_scroll(left_text, right_text, left_scroll, right_scroll)
        compare_pane.add(left_text.master.master, weight=1)
        compare_pane.add(right_text.master.master, weight=1)

    def _create_line_compare_panel(
        self, parent: ttk.Frame, colors: dict[str, str]
    ) -> dict[str, Text]:
        panel = ttk.Frame(parent, padding=(0, 3, 0, 0))
        panel.grid(row=1, column=0, sticky="ew")
        panel.columnconfigure(1, weight=1)
        ttk.Label(panel, text="선택 라인 비교").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 1)
        )
        ttk.Label(panel, text="왼쪽").grid(row=1, column=0, sticky="w", padx=(0, 4), pady=0)
        left = self._create_line_compare_text(panel, colors)
        left.grid(row=1, column=1, sticky="ew", pady=0)
        ttk.Label(panel, text="오른쪽").grid(row=2, column=0, sticky="w", padx=(0, 4), pady=0)
        right = self._create_line_compare_text(panel, colors)
        right.grid(row=2, column=1, sticky="ew", pady=0)
        x_scroll = ttk.Scrollbar(panel, orient="horizontal")
        x_scroll.grid(row=3, column=1, sticky="ew", pady=(0, 0))
        self._sync_line_compare_xscroll(left, right, x_scroll)
        return {"left": left, "right": right}

    def _create_line_compare_text(self, parent, colors: dict[str, str]) -> Text:
        text = Text(
            parent,
            height=1,
            wrap="none",
            undo=False,
            padx=0,
            pady=0,
            spacing1=0,
            spacing2=0,
            spacing3=0,
            bg=colors["detail_bg"],
            fg=colors["detail_fg"],
            insertbackground=colors["detail_fg"],
            selectbackground=colors["select_bg"],
            selectforeground=colors["select_fg"],
            font=self._detail_font(),
        )
        text.tag_configure(
            "char_diff",
            foreground=colors["compare_char_diff_fg"],
            underline=True,
        )
        text.configure(state="disabled")
        return text

    def _sync_line_compare_xscroll(
        self, left: Text, right: Text, scrollbar: ttk.Scrollbar
    ) -> None:
        syncing = {"active": False}

        def set_scroll(first: str, last: str, source: Text, target: Text) -> None:
            scrollbar.set(first, last)
            if syncing["active"]:
                return
            syncing["active"] = True
            target.xview_moveto(first)
            syncing["active"] = False

        def scroll_both(*args) -> None:
            left.xview(*args)
            right.xview(*args)

        left.configure(
            xscrollcommand=lambda first, last: set_scroll(first, last, left, right)
        )
        right.configure(
            xscrollcommand=lambda first, last: set_scroll(first, last, right, left)
        )
        scrollbar.configure(command=scroll_both)

    def _bind_compare_line_clicks(
        self,
        left_text: Text,
        right_text: Text,
        left_lines: list[str],
        right_lines: list[str],
        line_compare: dict[str, Text],
        colors: dict[str, str],
    ) -> None:
        for text in (left_text, right_text):
            text.tag_configure("clicked_line", background=colors["select_bg"])

        def select_line(event) -> str:
            try:
                line_index = int(event.widget.index(f"@{event.x},{event.y}").split(".")[0]) - 1
            except Exception:
                return "break"
            if line_index < 0 or line_index >= min(len(left_lines), len(right_lines)):
                return "break"
            for text in (left_text, right_text):
                text.tag_remove("clicked_line", "1.0", "end")
                line_no = line_index + 1
                text.tag_add("clicked_line", f"{line_no}.0", f"{line_no}.end")
            self._update_line_compare_panel(
                line_compare["left"],
                line_compare["right"],
                left_lines[line_index],
                right_lines[line_index],
            )
            return "break"

        left_text.bind("<Button-1>", select_line)
        right_text.bind("<Button-1>", select_line)
        for index, (left, right) in enumerate(zip(left_lines, right_lines)):
            if left != right:
                self._update_line_compare_panel(
                    line_compare["left"], line_compare["right"], left, right
                )
                left_text.tag_add("clicked_line", f"{index + 1}.0", f"{index + 1}.end")
                right_text.tag_add("clicked_line", f"{index + 1}.0", f"{index + 1}.end")
                break

    def _update_line_compare_panel(
        self, left_text: Text, right_text: Text, left_line: str, right_line: str
    ) -> None:
        self._set_line_compare_text(left_text, left_line)
        self._set_line_compare_text(right_text, right_line)
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
            None, left_line, right_line
        ).get_opcodes():
            if tag == "equal":
                continue
            if i1 != i2:
                left_text.tag_add("char_diff", f"1.0+{i1}c", f"1.0+{i2}c")
            if j1 != j2:
                right_text.tag_add("char_diff", f"1.0+{j1}c", f"1.0+{j2}c")

    def _set_line_compare_text(self, text: Text, value: str) -> None:
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", value)
        text.tag_remove("char_diff", "1.0", "end")
        text.configure(state="disabled")

    def _create_compare_side(
        self,
        parent: ttk.PanedWindow,
        title: str,
        lines: list[str],
        marks: list[str],
        colors: dict[str, str],
    ) -> tuple[Text, ttk.Scrollbar]:
        pane = ttk.Frame(parent)
        pane.columnconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)
        ttk.Label(pane, text=title).grid(row=0, column=0, sticky="w", pady=(0, 2))
        body = ttk.Frame(pane)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        wrap = "word" if self.detail_wrap_var.get() else "none"
        text = Text(
            body,
            wrap=wrap,
            height=8,
            undo=False,
            bg=colors["detail_bg"],
            fg=colors["detail_fg"],
            insertbackground=colors["detail_fg"],
            selectbackground=colors["select_bg"],
            selectforeground=colors["select_fg"],
            font=self._detail_font(),
        )
        y_scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=y_scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        if not self.detail_wrap_var.get():
            x_scroll = ttk.Scrollbar(body, orient="horizontal", command=text.xview)
            text.configure(xscrollcommand=x_scroll.set)
            x_scroll.grid(row=1, column=0, sticky="ew")

        text.tag_configure("replace", background=colors["compare_change_bg"])
        text.tag_configure("delete", background=colors["compare_delete_bg"])
        text.tag_configure("insert", background=colors["compare_insert_bg"])
        text.tag_configure(
            "match",
            background=colors["highlight_bg"],
            foreground=colors["highlight_fg"],
        )
        for line_no, (line, mark) in enumerate(zip(lines, marks), start=1):
            prefix = f"{line_no:>5}  "
            text.insert("end", prefix + line + "\n")
            if mark:
                text.tag_add(mark, f"{line_no}.0", f"{line_no}.end")
        self._highlight_detail_text(text)
        return text, y_scroll

    def _aligned_line_diff(
        self, left_lines: list[str], right_lines: list[str]
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
                    ["replace"] * len(left_chunk)
                    + ["insert"] * (count - len(left_chunk))
                )
                right_marks.extend(
                    ["replace"] * len(right_chunk)
                    + ["delete"] * (count - len(right_chunk))
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

    def _sync_compare_scroll(
        self,
        left_text: Text,
        right_text: Text,
        left_scroll: ttk.Scrollbar,
        right_scroll: ttk.Scrollbar,
    ) -> None:
        syncing = {"active": False}

        def scroll_both(first: str, last: str, source: Text, target: Text, scrollbar) -> None:
            scrollbar.set(first, last)
            if syncing["active"]:
                return
            syncing["active"] = True
            target.yview_moveto(first)
            syncing["active"] = False

        def command_both(*args, source: Text, target: Text) -> None:
            source.yview(*args)
            target.yview(*args)

        left_text.configure(
            yscrollcommand=lambda first, last: scroll_both(
                first, last, left_text, right_text, left_scroll
            )
        )
        right_text.configure(
            yscrollcommand=lambda first, last: scroll_both(
                first, last, right_text, left_text, right_scroll
            )
        )
        left_scroll.configure(
            command=lambda *args: command_both(*args, source=left_text, target=right_text)
        )
        right_scroll.configure(
            command=lambda *args: command_both(*args, source=right_text, target=left_text)
        )

    def _create_detail_pane(self, entry: LogEntry, index: int) -> ttk.Frame:
        pane = ttk.Frame(self.detail_pane)
        pane.columnconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)
        title = (
            f"#{index + 1}  {entry.display_time}  {entry.log_type.value}  "
            f"{entry.source_file}:{entry.line_no}"
        )
        ttk.Label(pane, text=title).grid(row=0, column=0, sticky="w", pady=(0, 2))
        body = ttk.Frame(pane)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        wrap = "word" if self.detail_wrap_var.get() else "none"
        colors = THEMES.get(self.theme_var.get(), THEMES["light"])
        detail_text = Text(
            body,
            wrap=wrap,
            height=8,
            undo=False,
            bg=colors["detail_bg"],
            fg=colors["detail_fg"],
            insertbackground=colors["detail_fg"],
            selectbackground=colors["select_bg"],
            selectforeground=colors["select_fg"],
            font=self._detail_font(),
        )
        detail_y_scroll = ttk.Scrollbar(body, orient="vertical", command=detail_text.yview)
        detail_text.configure(yscrollcommand=detail_y_scroll.set)
        detail_text.grid(row=0, column=0, sticky="nsew")
        detail_y_scroll.grid(row=0, column=1, sticky="ns")
        if not self.detail_wrap_var.get():
            detail_x_scroll = ttk.Scrollbar(
                body, orient="horizontal", command=detail_text.xview
            )
            detail_text.configure(xscrollcommand=detail_x_scroll.set)
            detail_x_scroll.grid(row=1, column=0, sticky="ew")

        detail_text.tag_configure(
            "match",
            background=colors["highlight_bg"],
            foreground=colors["highlight_fg"],
        )
        detail_text.tag_configure("selected_log", background=colors["select_bg"])
        detail = self._format_detail_with_context(index)
        detail_text.insert("1.0", detail)
        self._highlight_detail_text(detail_text)
        return pane

    def _format_detail_with_context(self, selected_index: int) -> str:
        context = max(0, self.context_rows_var.get())
        start = max(0, selected_index - context)
        end = min(len(self.filtered_entries), selected_index + context + 1)
        blocks: list[str] = []
        for index in range(start, end):
            if self.detail_header_var.get():
                prefix = ">>> 선택 로그" if index == selected_index else "    주변 로그"
                blocks.append(prefix)
            blocks.append(self._format_single_detail(self.filtered_entries[index], index))
        return "\n\n".join(blocks)

    def _format_single_detail(self, entry: LogEntry, index: int) -> str:
        message = entry.message
        message = _format_xml_in_message(message)
        if not self.detail_header_var.get():
            return message

        rows = self._visible_detail_header_rows(entry, index)
        if not rows:
            return message
        header = "\n".join(f"{field}: {value}" for field, value in rows)
        return f"{header}\n\n{message}"

    def _visible_detail_header_rows(
        self, entry: LogEntry, index: int
    ) -> list[tuple[str, str]]:
        values = dict(
            zip(
                COLUMNS,
                _entry_to_values(
                    entry,
                    self.matched_keywords_by_entry.get(id(entry), ""),
                    self._is_bookmarked(entry),
                    self._entry_memo(entry),
                ),
            )
        )
        values["line"] = str(entry.line_no)
        rows: list[tuple[str, str]] = []
        for column in self.visible_columns:
            if column == "message":
                continue
            value = values.get(column, "")
            if column in {"bookmark", "memo"} and not value:
                continue
            rows.append((COLUMN_LABELS[column], value))
        return rows

    def _highlight_detail_text(self, detail_text: Text) -> None:
        flags = 0 if self.case_sensitive_var.get() else re.IGNORECASE
        content = detail_text.get("1.0", "end-1c")
        for keyword in self._highlight_terms():
            pattern_text = keyword if self.regex_search_var.get() else re.escape(keyword)
            try:
                pattern = re.compile(pattern_text, flags)
            except re.error:
                pattern = re.compile(re.escape(keyword), flags)
            for match in pattern.finditer(content):
                if match.start() == match.end():
                    continue
                start = f"1.0+{match.start()}c"
                end = f"1.0+{match.end()}c"
                detail_text.tag_add("match", start, end)

    def _clear_detail(self) -> None:
        for child in self.detail_pane_container.winfo_children():
            child.destroy()

    def export_csv(self) -> None:
        if not self.filtered_entries:
            messagebox.showinfo("CSV 저장", "저장할 데이터가 없습니다.")
            return
        path = filedialog.asksaveasfilename(
            title="CSV 저장",
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow([COLUMN_LABELS[column] for column in COLUMNS])
            for entry in self.filtered_entries:
                writer.writerow(
                    _entry_to_values(
                        entry,
                        self.matched_keywords_by_entry.get(id(entry), ""),
                        self._is_bookmarked(entry),
                        self._entry_memo(entry),
                    )
                )
        self.status_var.set(f"CSV 저장 완료: {path}")

    def export_report(self) -> None:
        if not self.entries:
            messagebox.showinfo("리포트 저장", "먼저 로그를 분석하세요.")
            return
        path = filedialog.asksaveasfilename(
            title="리포트 저장",
            defaultextension=".md",
            filetypes=(("Markdown", "*.md"), ("Text", "*.txt"), ("All files", "*.*")),
        )
        if not path:
            return
        report_format = "txt" if path.lower().endswith(".txt") else "markdown"
        report = generate_report(
            self.filtered_entries or self.entries,
            self.gem300_events,
            self.alarms,
            self.search_matches,
            keyword=self._filter_description(),
            skipped_setup_lines=self.skipped_setup_lines,
            file_summary=self.file_types,
            format=report_format,
        )
        Path(path).write_text(report, encoding="utf-8")
        self.status_var.set(f"리포트 저장 완료: {path}")

    def _filter_description(self) -> str:
        parts: list[str] = []
        and_keywords = [keyword for mode, keyword in self.keywords if mode == "AND"]
        or_keywords = [keyword for mode, keyword in self.keywords if mode == "OR"]
        if and_keywords:
            parts.append("AND: " + ", ".join(and_keywords))
        if or_keywords:
            parts.append("OR: " + ", ".join(or_keywords))
        if self.exclude_keywords:
            parts.append("제외: " + ", ".join(self.exclude_keywords))
        return " / ".join(parts)

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    Gem300DesktopApp().run()


if __name__ == "__main__":
    main()

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
from collections import Counter
from datetime import datetime, timedelta
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

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
APP_ICON_PNG = ROOT / "assets" / "app_icon.png"
APP_ICON_ICO = ROOT / "assets" / "app_icon.ico"
WINDOWS_APP_ID = "BOC.GEM300LogAnalyzer.Desktop"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gem300_log_analyzer import __version__
from gem300_log_analyzer.analysis.alarm_summary import extract_alarms, is_alarm_entry, summarize_alarms
from gem300_log_analyzer.analysis.carrier_roundtrip import (
    CarrierRoundtripRow,
    build_carrier_roundtrip,
)
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
from gem300_log_analyzer.parsers.log_loader import is_supported_log_path, parse_paths
from gem300_log_analyzer.ui.desktop_helpers import (
    aligned_line_diff,
    calculate_flow_positions as _calculate_flow_positions,
    entry_to_values as _entry_to_values,
    format_entries_for_clipboard,
    format_entry_for_clipboard,
    format_time_delta,
    format_time_filter_input,
    format_xml_in_message as _format_xml_in_message,
    layout_responsive_flow,
    parse_custom_time_filter_inputs,
    parse_time_filter_input,
    sxfy_label as _sxfy_label,
)

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None


COLUMNS = (
    "bookmark",
    "memo",
    "time",
    "time_delta",
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
    "time_delta": "간격",
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
    "time_delta": 90,
    "type": 70,
    "matched_keywords": 160,
    "level_channel": 90,
    "ceid": 80,
    "event_name": 220,
    "file": 170,
    "line": 70,
    "message": 620,
}

MAX_ALL_LOGS_WINDOW_ROWS = 10_000
TIME_FILTER_WINDOWS = (
    ("앞뒤 1초", 1),
    ("앞뒤 5초", 5),
    ("앞뒤 30초", 30),
    ("앞뒤 1분", 60),
    ("앞뒤 5분", 5 * 60),
    ("앞뒤 10분", 10 * 60),
    ("앞뒤 30분", 30 * 60),
    ("앞뒤 1시간", 60 * 60),
)
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
        "flow_highlight_bg": "#dbeafe",
        "flow_highlight_fg": "#1e3a8a",
        "compare_change_bg": "#fff3b0",
        "compare_delete_bg": "#ffd6d6",
        "compare_insert_bg": "#d8f5d0",
        "compare_char_diff_fg": "#dc2626",
        "grip_bg": "#e5e7eb",
        "grip_line": "#94a3b8",
        "grip_dot": "#475569",
    },
    "dark": {
        "bg": "#1e1e1e",
        "panel": "#252526",
        "text": "#cccccc",
        "muted": "#9d9d9d",
        "field": "#1e1e1e",
        "border": "#3c3c3c",
        "accent": "#3c3c3c",
        "select_bg": "#3a3d41",
        "select_fg": "#ffffff",
        "tree_bg": "#1e1e1e",
        "tree_alt": "#2d2d30",
        "detail_bg": "#1e1e1e",
        "detail_fg": "#d4d4d4",
        "highlight_bg": "#4b4b4b",
        "highlight_fg": "#ffffff",
        "flow_highlight_bg": "#333333",
        "flow_highlight_fg": "#ffffff",
        "compare_change_bg": "#3d3a24",
        "compare_delete_bg": "#4a2f2f",
        "compare_insert_bg": "#2f4232",
        "compare_char_diff_fg": "#f48771",
        "grip_bg": "#2d2d30",
        "grip_line": "#3c3c3c",
        "grip_dot": "#cccccc",
    },
}

CARRIER_ROUNDTRIP_TIMELINE_ENABLED = False
STARTUP_SMOKE_MARKER_ENV = "GEM300_STARTUP_SMOKE_MARKER"

SXFy_RE = re.compile(r"\bS(?P<stream>\d+)F(?P<function>\d+)(?:W)?\b", re.IGNORECASE)


class Gem300DesktopApp:
    def __init__(self) -> None:
        self._set_windows_app_id()
        self.root = TkinterDnD.Tk() if TkinterDnD is not None else Tk()
        self.root.title(f"GEM300 Log Analyzer v{__version__}")
        self.root.withdraw()
        self._set_window_icon()
        self.startup_splash = self._show_startup_splash()
        self.root.geometry("1400x820")
        self.root.minsize(1050, 640)

        self.paths: list[str] = []
        self.analyzed_paths: list[str] = []
        self.entries: list[LogEntry] = []
        self.filtered_entries: list[LogEntry] = []
        self.search_matches: list[SearchMatch] = []
        self.time_filter_start: datetime | None = None
        self.time_filter_end: datetime | None = None
        self.log_view_layout_active = False
        self.search_view_mode_active = False
        self._detail_source = "filtered"
        self._filter_generation = 0
        self._bookmark_timeline_updating = False
        self._bookmark_timeline_jump_running = False
        self._pending_filter_restore_key: str | None = None
        self.skipped_setup_lines = 0
        self.file_types: dict[str, str] = {}
        self.gem300_events = []
        self.alarms = []
        self.carrier_roundtrip_rows: list[CarrierRoundtripRow] = []
        self.roundtrip_row_refs: dict[str, CarrierRoundtripRow] = {}
        self.report_variables: dict[int, list[ReportVariable]] = {}
        self.settings = self._load_settings()
        self.bookmarks: dict[str, str] = self._load_bookmarks()
        self.sxfy_types: list[str] = []
        self.sxfy_filter_vars: dict[str, BooleanVar] = {}

        self.keyword_var = StringVar()
        self.result_search_var = StringVar()
        self.carrier_roundtrip_var = StringVar()
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
        self.bookmark_only_var = BooleanVar(
            value=bool(self.settings.get("bookmark_only_filter", False))
        )
        self.always_include_bookmarks_var = BooleanVar(
            value=bool(self.settings.get("always_include_bookmarks", False))
        )
        self.bookmark_timeline_visible_var = BooleanVar(
            value=bool(self.settings.get("bookmark_timeline_visible", True))
        )
        self.stats_panel_visible_var = BooleanVar(
            value=bool(self.settings.get("stats_panel_visible", True))
        )
        self.skip_setup_var = BooleanVar(value=True)
        self.options_expanded_var = BooleanVar(
            value=bool(self.settings.get("options_panel_expanded", False))
        )
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
        self.flow_highlight_var = BooleanVar(
            value=bool(self.settings.get("flow_highlight_enabled", True))
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
        self.bookmark_timeline_title_var = StringVar(value="북마크 타임라인")
        self.time_filter_summary_var = StringVar(value="시간 필터 없음")
        self._column_drag_source: str | None = None
        self.visible_columns = self._load_visible_columns()
        self.column_visible_vars: dict[str, BooleanVar] = {
            column: BooleanVar(value=column in self.visible_columns)
            for column in COLUMNS
        }

        self._build_ui()
        self._finish_startup_splash()


    def _show_startup_splash(self) -> Toplevel:
        splash = Toplevel(self.root)
        splash.overrideredirect(True)
        splash.configure(bg="#1e1e1e")
        splash.attributes("-topmost", True)
        width = 420
        height = 170
        screen_width = splash.winfo_screenwidth()
        screen_height = splash.winfo_screenheight()
        x = max(0, int((screen_width - width) / 2))
        y = max(0, int((screen_height - height) / 2))
        splash.geometry(f"{width}x{height}+{x}+{y}")

        style = ttk.Style(splash)
        style.configure("Splash.TFrame", background="#1e1e1e")
        style.configure("SplashTitle.TLabel", background="#1e1e1e", foreground="#cccccc")
        style.configure("SplashBody.TLabel", background="#1e1e1e", foreground="#9d9d9d")

        frame = ttk.Frame(splash, padding=(28, 24, 28, 20), style="Splash.TFrame")
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=f"GEM300 Log Analyzer v{__version__}",
            font=("Segoe UI", 15, "bold"),
            style="SplashTitle.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text="프로그램 시작 중입니다...",
            font=("Segoe UI", 10),
            style="SplashBody.TLabel",
        ).pack(anchor="w", pady=(16, 12))
        progress = ttk.Progressbar(frame, mode="indeterminate", length=340)
        progress.pack(fill="x")
        progress.start(12)
        self.root.update_idletasks()
        splash.update()
        return splash

    def _finish_startup_splash(self) -> None:
        self.root.update_idletasks()
        splash = getattr(self, "startup_splash", None)
        if splash is not None:
            try:
                splash.destroy()
            except Exception:
                pass
            self.startup_splash = None
        self.root.deiconify()
        self.root.after(0, self._maximize_window)

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
        self.root.rowconfigure(4, weight=1)

        self._responsive_flows: dict[object, dict[str, object]] = {}

        self.toolbar_frame = ttk.Frame(self.root)
        self.toolbar_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
        toolbar_items = [
            ttk.Button(self.toolbar_frame, text="파일 선택", command=self.choose_files),
            ttk.Button(self.toolbar_frame, text="분석", command=self.analyze),
            ttk.Button(
                self.toolbar_frame,
                text="분석 파일 목록",
                command=self.show_analysis_files,
            ),
            ttk.Button(self.toolbar_frame, text="초기화", command=self.reset_analysis),
            ttk.Button(self.toolbar_frame, text="세션 저장", command=self.save_session),
            ttk.Button(self.toolbar_frame, text="세션 불러오기", command=self.load_session),
            ttk.Button(self.toolbar_frame, text="CSV 저장", command=self.export_csv),
            ttk.Button(self.toolbar_frame, text="리포트 저장", command=self.export_report),
            ttk.Button(
                self.toolbar_frame,
                text="로그 보기 전용",
                command=self.activate_log_view_layout,
            ),
            ttk.Button(
                self.toolbar_frame,
                text="검색 화면",
                command=self.activate_search_view_mode,
            ),
            ttk.Button(
                self.toolbar_frame,
                text="기본 레이아웃",
                command=self.restore_default_layout,
            ),
            ttk.Label(self.toolbar_frame, textvariable=self.summary_var),
            ttk.Checkbutton(
                self.toolbar_frame,
                text="상세 옵션",
                variable=self.options_expanded_var,
                command=self.toggle_options_panel,
            ),
        ]
        self._register_responsive_flow(
            self.toolbar_frame, toolbar_items, gap=6, stretch_index=11
        )

        self.quick_search_frame = ttk.Frame(self.root)
        self.quick_search_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))

        include_group = ttk.Frame(self.quick_search_frame)
        ttk.Label(include_group, text="포함").grid(row=0, column=0, padx=(0, 4))
        keyword_entry = ttk.Entry(include_group, textvariable=self.keyword_var, width=28)
        keyword_entry.grid(row=0, column=1, padx=(0, 6))
        keyword_entry.bind("<Return>", lambda _event: self.add_keyword())
        ttk.Combobox(
            include_group,
            textvariable=self.keyword_mode_var,
            values=("AND", "OR"),
            width=5,
            state="readonly",
        ).grid(row=0, column=2, padx=(0, 6))
        ttk.Button(include_group, text="추가/수정", command=self.add_keyword).grid(
            row=0, column=3
        )

        exclude_group = ttk.Frame(self.quick_search_frame)
        ttk.Label(exclude_group, text="제외").grid(row=0, column=0, padx=(0, 4))
        exclude_keyword_entry = ttk.Entry(
            exclude_group, textvariable=self.exclude_keyword_var, width=28
        )
        exclude_keyword_entry.grid(row=0, column=1, padx=(0, 6))
        exclude_keyword_entry.bind("<Return>", lambda _event: self.add_exclude_keyword())
        ttk.Button(exclude_group, text="추가", command=self.add_exclude_keyword).grid(
            row=0, column=2
        )

        apply_filter_button = ttk.Button(
            self.quick_search_frame,
            text="검색/필터 적용(F5)",
            command=self.apply_filters,
        )
        result_group = ttk.Frame(self.quick_search_frame)
        ttk.Label(result_group, text="결과 내").grid(row=0, column=0, padx=(0, 4))
        result_search_entry = ttk.Entry(
            result_group, textvariable=self.result_search_var, width=24
        )
        result_search_entry.grid(row=0, column=1, padx=(0, 6))
        result_search_entry.bind(
            "<Return>", lambda event: self.find_result_match(1, event)
        )
        ttk.Button(
            result_group,
            text="이전(F3)",
            command=lambda: self.find_result_match(-1),
        ).grid(row=0, column=2, padx=(0, 4))
        ttk.Button(
            result_group,
            text="다음(F4)",
            command=lambda: self.find_result_match(1),
        ).grid(row=0, column=3, padx=(0, 4))
        ttk.Button(result_group, text="지우기", command=self.clear_result_search).grid(
            row=0, column=4
        )
        self.sxfy_button = ttk.Menubutton(self.quick_search_frame, text="SxFy 필터")
        self.sxfy_menu = Menu(self.sxfy_button, tearoff=False)
        self.sxfy_button["menu"] = self.sxfy_menu
        self._build_sxfy_menu()
        self._register_responsive_flow(
            self.quick_search_frame,
            [
                include_group,
                exclude_group,
                apply_filter_button,
                result_group,
                self.sxfy_button,
            ],
            gap=12,
        )
        self.options_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        self.options_frame.grid(row=2, column=0, sticky="ew")
        self.options_frame.columnconfigure(0, weight=1)
        self.options_notebook = ttk.Notebook(self.options_frame)
        self.options_notebook.grid(row=0, column=0, sticky="ew")

        search_tab = ttk.Frame(self.options_notebook, padding=(8, 8))
        filter_tab = ttk.Frame(self.options_notebook, padding=(8, 8))
        db_tab = ttk.Frame(self.options_notebook, padding=(8, 8))
        view_tab = ttk.Frame(self.options_notebook, padding=(8, 8))
        self.options_notebook.add(search_tab, text="검색 조건")
        self.options_notebook.add(filter_tab, text="로그 필터")
        self.options_notebook.add(db_tab, text="DB/주석")
        self.options_notebook.add(view_tab, text="보기 설정")

        search_tab.columnconfigure(0, weight=1)
        search_tab.columnconfigure(1, weight=1)
        search_options = ttk.Frame(search_tab)
        search_options.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Checkbutton(
            search_options,
            text="대소문자 구분",
            variable=self.case_sensitive_var,
            command=self.on_search_option_changed,
        ).grid(row=0, column=0, padx=(0, 12))
        ttk.Checkbutton(
            search_options,
            text="정규식 검색",
            variable=self.regex_search_var,
            command=self.on_search_option_changed,
        ).grid(row=0, column=1, padx=(0, 18))
        ttk.Label(search_options, text="프리셋").grid(row=0, column=2, padx=(0, 4))
        ttk.Entry(search_options, textvariable=self.preset_name_var, width=18).grid(
            row=0, column=3, padx=(0, 6)
        )
        ttk.Button(search_options, text="저장", command=self.save_search_preset).grid(
            row=0, column=4, padx=(0, 6)
        )
        preset_button = ttk.Menubutton(search_options, text="불러오기")
        preset_button.grid(row=0, column=5, padx=(0, 6))
        self.preset_menu = Menu(preset_button, tearoff=False)
        preset_button["menu"] = self.preset_menu
        ttk.Button(search_options, text="삭제", command=self.delete_search_preset).grid(
            row=0, column=6
        )
        self._build_preset_menu()

        include_panel = ttk.Frame(search_tab)
        include_panel.grid(row=1, column=0, sticky="ew", padx=(0, 8))
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
        self.keyword_tag_text.bind("<Escape>", self.clear_selected_keyword)
        include_buttons = ttk.Frame(include_panel)
        include_buttons.grid(row=2, column=0, sticky="e")
        ttk.Button(
            include_buttons, text="선택 삭제", command=self.remove_selected_keyword
        ).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(include_buttons, text="전체 삭제", command=self.clear_keywords).grid(
            row=0, column=1
        )

        exclude_panel = ttk.Frame(search_tab)
        exclude_panel.grid(row=1, column=1, sticky="ew", padx=(8, 0))
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
        self.exclude_keyword_tag_text.bind(
            "<Escape>", self.clear_selected_exclude_keyword
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
        ttk.Checkbutton(
            search_tab,
            text="북마크는 포함/제외 키워드 조건과 관계없이 표시",
            variable=self.always_include_bookmarks_var,
            command=self.on_always_include_bookmarks_changed,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        filter_tab.columnconfigure(9, weight=1)
        ttk.Checkbutton(
            filter_tab,
            text="MMI",
            variable=self.filter_mmi_var,
            command=self.apply_filters,
        ).grid(row=0, column=0, padx=(0, 8))
        ttk.Checkbutton(
            filter_tab,
            text="SECS/GEM",
            variable=self.filter_secs_var,
            command=self.apply_filters,
        ).grid(row=0, column=1, padx=(0, 12))
        ttk.Checkbutton(
            filter_tab,
            text="북마크만 보기",
            variable=self.bookmark_only_var,
            command=self.on_bookmark_only_changed,
        ).grid(row=0, column=2, padx=(0, 12))
        ttk.Checkbutton(
            filter_tab,
            text="Setup.ini 덤프 제외",
            variable=self.skip_setup_var,
        ).grid(row=0, column=3, padx=(0, 18))
        ttk.Label(filter_tab, text="표시 행").grid(row=0, column=4, padx=(0, 4))
        ttk.Spinbox(
            filter_tab,
            from_=100,
            to=100000,
            increment=100,
            textvariable=self.display_rows_var,
            width=8,
            command=self.refresh_table,
        ).grid(row=0, column=5, padx=(0, 18))
        ttk.Checkbutton(
            filter_tab,
            text="S6F11 CEID 제외",
            variable=self.exclude_s6f11_var,
            command=self.save_s6f11_exclude_settings,
        ).grid(row=0, column=6, padx=(0, 4))
        ttk.Label(
            filter_tab,
            textvariable=self.exclude_ceid_summary_var,
            width=18,
            anchor="w",
        ).grid(row=0, column=7, padx=(0, 6), sticky="w")
        ttk.Button(
            filter_tab,
            text="CEID 편집",
            command=self.open_ceid_exclude_editor,
        ).grid(row=0, column=8, padx=(0, 12))
        ttk.Label(filter_tab, text="시간 범위").grid(row=1, column=0, padx=(0, 4), pady=(8, 0))
        self.time_filter_button = ttk.Menubutton(filter_tab, text="선택 로그 기준")
        self.time_filter_button.grid(row=1, column=1, sticky="w", pady=(8, 0))
        self.time_filter_menu = Menu(self.time_filter_button, tearoff=False)
        self.time_filter_button["menu"] = self.time_filter_menu
        self._build_time_filter_menu()
        ttk.Button(
            filter_tab, text="직접 지정", command=self.open_custom_time_filter_dialog
        ).grid(row=1, column=2, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Label(filter_tab, textvariable=self.time_filter_summary_var).grid(
            row=1, column=3, columnspan=5, sticky="w", padx=(8, 0), pady=(8, 0)
        )

        self.db_frame = db_tab
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

        view_tab.columnconfigure(5, weight=1)
        column_button = ttk.Menubutton(view_tab, text="컬럼 설정")
        column_button.grid(row=0, column=0, padx=(0, 10))
        self.column_menu = Menu(column_button, tearoff=False)
        column_button["menu"] = self.column_menu
        self._build_column_menu()
        ttk.Label(view_tab, text="테마").grid(row=0, column=1, padx=(0, 4))
        ttk.Combobox(
            view_tab,
            textvariable=self.theme_var,
            values=("light", "dark"),
            width=7,
            state="readonly",
        ).grid(row=0, column=2, padx=(0, 18))
        self.theme_var.trace_add("write", lambda *_args: self.on_theme_changed())
        ttk.Checkbutton(
            view_tab,
            text="북마크 타임라인",
            variable=self.bookmark_timeline_visible_var,
            command=self.on_bookmark_timeline_visibility_changed,
        ).grid(row=0, column=3, padx=(0, 18))
        ttk.Checkbutton(
            view_tab,
            text="통계 패널",
            variable=self.stats_panel_visible_var,
            command=self.on_stats_panel_visibility_changed,
        ).grid(row=0, column=4, padx=(0, 18))
        ttk.Label(view_tab, text="상세 로그 폰트/비교/헤더 옵션은 상세 영역에서 조정합니다.").grid(
            row=0, column=5, sticky="w"
        )

        self.toggle_options_panel(save=False)

        self.drop_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        self.drop_frame.grid(row=3, column=0, sticky="ew")
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
        self.content_pane.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 8))

        self.table_frame = ttk.Frame(self.content_pane)
        self.table_frame.columnconfigure(0, weight=1)
        self.table_frame.rowconfigure(0, weight=1)

        self.search_view_pane = ttk.PanedWindow(
            self.table_frame,
            orient="horizontal",
        )
        self.search_view_pane.grid(row=0, column=0, sticky="nsew")

        self.all_logs_frame = ttk.Frame(self.search_view_pane)
        self.all_logs_frame.columnconfigure(0, weight=1)
        self.all_logs_frame.rowconfigure(1, weight=1)
        self.all_logs_title_var = StringVar(value="전체 로그")
        ttk.Label(
            self.all_logs_frame,
            textvariable=self.all_logs_title_var,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self.all_logs_tree = ttk.Treeview(
            self.all_logs_frame,
            columns=COLUMNS,
            show="headings",
            selectmode="browse",
        )
        for column in COLUMNS:
            self.all_logs_tree.heading(column, text=COLUMN_LABELS[column])
            self.all_logs_tree.column(
                column,
                width=COLUMN_WIDTHS[column],
                minwidth=50,
                stretch=column == "message",
                anchor="w",
            )
        self.all_logs_tree.configure(displaycolumns=self.visible_columns)
        all_logs_y_scroll = ttk.Scrollbar(
            self.all_logs_frame,
            orient="vertical",
            command=self.all_logs_tree.yview,
        )
        all_logs_x_scroll = ttk.Scrollbar(
            self.all_logs_frame,
            orient="horizontal",
            command=self.all_logs_tree.xview,
        )
        self.all_logs_tree.configure(
            yscrollcommand=all_logs_y_scroll.set,
            xscrollcommand=all_logs_x_scroll.set,
        )
        self.all_logs_tree.tag_configure("bookmarked", background="#fff7cc")
        self.all_logs_tree.bind("<ButtonRelease-1>", self.show_selected_full_log_detail)
        self.all_logs_tree.grid(row=1, column=0, sticky="nsew")
        all_logs_y_scroll.grid(row=1, column=1, sticky="ns")
        all_logs_x_scroll.grid(row=2, column=0, sticky="ew")

        self.result_area_frame = ttk.Frame(self.search_view_pane)
        self.result_area_frame.columnconfigure(0, weight=1)
        self.result_area_frame.rowconfigure(0, weight=1)
        self.search_view_pane.add(self.result_area_frame, weight=1)

        self.result_area_pane = ttk.PanedWindow(
            self.result_area_frame,
            orient="horizontal",
        )
        self.result_area_pane.grid(row=0, column=0, sticky="nsew")

        self.filtered_table_frame = ttk.Frame(self.result_area_pane)
        self.filtered_table_frame.columnconfigure(0, weight=1)
        self.filtered_table_frame.rowconfigure(1, weight=1)
        self.filtered_result_title_var = StringVar(value="필터 결과")
        ttk.Label(
            self.filtered_table_frame,
            textvariable=self.filtered_result_title_var,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self.tree = ttk.Treeview(
            self.filtered_table_frame,
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
        y_scroll = ttk.Scrollbar(
            self.filtered_table_frame,
            orient="vertical",
            command=self.tree.yview,
        )
        x_scroll = ttk.Scrollbar(
            self.filtered_table_frame,
            orient="horizontal",
            command=self.tree.xview,
        )
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.tag_configure("bookmarked", background="#fff7cc")
        self.result_context_menu = Menu(self.tree, tearoff=False)
        self.result_context_menu.add_command(
            label="선택 로그 원문 복사",
            command=self.copy_selected_logs_to_clipboard,
        )
        self.tree.grid(row=1, column=0, sticky="nsew")
        y_scroll.grid(row=1, column=1, sticky="ns")
        x_scroll.grid(row=2, column=0, sticky="ew")
        self.result_area_pane.add(self.filtered_table_frame, weight=4)

        self.result_sidebar_frame = ttk.Frame(self.result_area_pane, padding=(8, 0, 0, 0))
        self.result_sidebar_frame.columnconfigure(0, weight=1)
        self.result_sidebar_frame.rowconfigure(0, weight=3)
        self.result_sidebar_frame.rowconfigure(1, weight=1)
        self.result_area_pane.add(self.result_sidebar_frame, weight=1)

        self.bookmark_timeline_frame = ttk.Frame(self.result_sidebar_frame)
        self.bookmark_timeline_frame.grid(row=0, column=0, sticky="nsew")
        self.bookmark_timeline_frame.columnconfigure(0, weight=1)
        self.bookmark_timeline_frame.rowconfigure(1, weight=1)
        ttk.Label(
            self.bookmark_timeline_frame,
            textvariable=self.bookmark_timeline_title_var,
        ).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 4)
        )
        self.bookmark_timeline = ttk.Treeview(
            self.bookmark_timeline_frame,
            columns=("time", "type", "memo"),
            show="headings",
            selectmode="browse",
            height=8,
        )
        self.bookmark_timeline.heading("time", text="시간")
        self.bookmark_timeline.heading("type", text="타입")
        self.bookmark_timeline.heading("memo", text="메모")
        self.bookmark_timeline.column("time", width=145, minwidth=110, stretch=False)
        self.bookmark_timeline.column("type", width=55, minwidth=45, stretch=False)
        self.bookmark_timeline.column("memo", width=140, minwidth=80, stretch=True)
        bookmark_scroll = ttk.Scrollbar(
            self.bookmark_timeline_frame,
            orient="vertical",
            command=self.bookmark_timeline.yview,
        )
        self.bookmark_timeline.configure(yscrollcommand=bookmark_scroll.set)
        self.bookmark_timeline.grid(row=1, column=0, sticky="nsew")
        bookmark_scroll.grid(row=1, column=1, sticky="ns")
        self.bookmark_timeline.bind(
            "<<TreeviewSelect>>", self.on_bookmark_timeline_select
        )
        self._apply_bookmark_timeline_visibility(save=False)
        self.stats_frame = ttk.Frame(self.result_sidebar_frame, padding=(0, 8, 0, 0))
        self.stats_frame.grid(row=1, column=0, sticky="nsew")
        self.stats_frame.columnconfigure(0, weight=1)
        self.stats_frame.rowconfigure(1, weight=1)
        ttk.Label(self.stats_frame, text="필터 결과 통계").grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )
        self.stats_text = Text(
            self.stats_frame,
            width=40,
            height=10,
            wrap="none",
            borderwidth=1,
            relief="solid",
            font=("Consolas", 9),
            state="disabled",
        )
        self.stats_text.grid(row=1, column=0, sticky="nsew")
        self._apply_stats_panel_visibility(save=False)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_detail)
        self.tree.bind(
            "<<TreeviewSelect>>",
            self.on_filtered_result_selected_in_search_mode,
            add="+",
        )
        self.tree.bind("<Control-a>", self.select_all_filtered_logs)
        self.tree.bind("<Control-Button-1>", self._on_tree_control_click)
        self.tree.bind("<ButtonPress-1>", self._on_tree_button_press)
        self.tree.bind("<B1-Motion>", self._on_tree_drag_motion, add="+")
        self.tree.bind("<ButtonRelease-1>", self._on_tree_button_release, add="+")
        self.tree.bind("<Motion>", self._on_tree_motion, add="+")
        self.tree.bind("<Leave>", self._on_tree_leave, add="+")
        self.tree.bind("<Button-3>", self._on_tree_right_click, add="+")
        self.root.bind("<F3>", lambda event: self.find_result_match(-1, event))
        self.root.bind("<F4>", lambda event: self.find_result_match(1, event))
        self.root.bind("<F5>", self.apply_filters_shortcut)
        self.content_pane.add(self.table_frame, weight=4)

        self.roundtrip_frame = ttk.Frame(self.content_pane)
        self.roundtrip_frame.columnconfigure(0, weight=1)
        self.roundtrip_frame.rowconfigure(1, weight=1)
        roundtrip_header = ttk.Frame(self.roundtrip_frame)
        roundtrip_header.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        roundtrip_header.columnconfigure(4, weight=1)
        ttk.Label(roundtrip_header, text="Carrier Roundtrip Timeline").grid(
            row=0, column=0, sticky="w", padx=(0, 10)
        )
        ttk.Label(roundtrip_header, text="Carrier ID").grid(row=0, column=1, padx=(0, 4))
        roundtrip_entry = ttk.Entry(
            roundtrip_header,
            textvariable=self.carrier_roundtrip_var,
            width=28,
        )
        roundtrip_entry.grid(row=0, column=2, padx=(0, 6))
        roundtrip_entry.bind("<Return>", lambda _event: self.refresh_carrier_roundtrip())
        ttk.Button(
            roundtrip_header,
            text="조회",
            command=self.refresh_carrier_roundtrip,
        ).grid(row=0, column=3, padx=(0, 8))
        ttk.Label(
            roundtrip_header,
            text="row 선택 시 원본 로그로 이동",
        ).grid(row=0, column=4, sticky="w")
        self.roundtrip_tree = ttk.Treeview(
            self.roundtrip_frame,
            columns=("time", "gap", "port", "level", "state", "detail", "source", "line"),
            show="headings",
            selectmode="browse",
            height=7,
        )
        for column, label, width, stretch in (
            ("time", "시간", 160, False),
            ("gap", "간격", 80, False),
            ("port", "Port", 70, False),
            ("level", "Level", 70, False),
            ("state", "State/Event", 210, False),
            ("detail", "Detail", 520, True),
            ("source", "Source", 70, False),
            ("line", "Line", 70, False),
        ):
            self.roundtrip_tree.heading(column, text=label)
            self.roundtrip_tree.column(column, width=width, minwidth=50, stretch=stretch, anchor="w")
        roundtrip_y_scroll = ttk.Scrollbar(
            self.roundtrip_frame,
            orient="vertical",
            command=self.roundtrip_tree.yview,
        )
        self.roundtrip_tree.configure(yscrollcommand=roundtrip_y_scroll.set)
        self.roundtrip_tree.tag_configure("WARN", background="#fff7cc")
        self.roundtrip_tree.tag_configure("ERROR", background="#ffd6d6")
        self.roundtrip_tree.grid(row=1, column=0, sticky="nsew")
        roundtrip_y_scroll.grid(row=1, column=1, sticky="ns")
        self.roundtrip_tree.bind("<<TreeviewSelect>>", self.on_roundtrip_row_select)
        if CARRIER_ROUNDTRIP_TIMELINE_ENABLED:
            self.content_pane.add(self.roundtrip_frame, weight=1)

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
        self.detail_header = ttk.Frame(self.detail_frame)
        self.detail_header.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        detail_items: list[object] = [
            ttk.Label(self.detail_header, text="선택 로그 상세"),
            ttk.Checkbutton(
                self.detail_header,
                text="상세 가로 보기",
                variable=self.detail_horizontal_var,
                command=self.refresh_selected_detail,
            ),
            ttk.Checkbutton(
                self.detail_header,
                text="긴 로그 줄바꿈",
                variable=self.detail_wrap_var,
                command=self.refresh_selected_detail,
            ),
            ttk.Checkbutton(
                self.detail_header,
                text="헤더 표시",
                variable=self.detail_header_var,
                command=self.on_detail_header_changed,
            ),
            ttk.Checkbutton(
                self.detail_header,
                text="비교 보기",
                variable=self.compare_mode_var,
                command=self.on_compare_mode_changed,
            ),
        ]

        context_group = ttk.Frame(self.detail_header)
        ttk.Label(context_group, text="앞뒤").grid(row=0, column=0, padx=(0, 2))
        ttk.Spinbox(
            context_group,
            from_=0,
            to=200,
            increment=1,
            textvariable=self.context_rows_var,
            width=5,
            command=self.on_context_rows_changed,
        ).grid(row=0, column=1)
        detail_items.append(context_group)
        detail_items.append(
            ttk.Checkbutton(
                self.detail_header,
                text="ID 흐름 강조",
                variable=self.flow_highlight_var,
                command=self.on_flow_highlight_changed,
            )
        )

        font_group = ttk.Frame(self.detail_header)
        ttk.Label(font_group, text="폰트").grid(row=0, column=0, padx=(0, 2))
        self.detail_font_combo = ttk.Combobox(
            font_group,
            textvariable=self.detail_font_family_var,
            values=DETAIL_FONT_VALUES,
            width=14,
            state="readonly",
        )
        self.detail_font_combo.grid(row=0, column=1)
        self.detail_font_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self.on_detail_font_changed()
        )
        detail_items.append(font_group)

        font_size_group = ttk.Frame(self.detail_header)
        ttk.Label(font_size_group, text="크기").grid(row=0, column=0, padx=(0, 2))
        detail_font_size_spin = ttk.Spinbox(
            font_size_group,
            from_=7,
            to=32,
            increment=1,
            textvariable=self.detail_font_size_var,
            width=4,
            command=self.on_detail_font_changed,
        )
        detail_font_size_spin.grid(row=0, column=1)
        detail_font_size_spin.bind(
            "<FocusOut>", lambda _event: self.on_detail_font_changed()
        )
        detail_font_size_spin.bind(
            "<Return>", lambda _event: self.on_detail_font_changed()
        )
        detail_items.extend(
            [
                font_size_group,
                ttk.Button(
                    self.detail_header,
                    text="북마크",
                    command=self.toggle_selected_bookmarks,
                ),
                ttk.Button(
                    self.detail_header, text="메모", command=self.edit_selected_memo
                ),
                ttk.Button(
                    self.detail_header,
                    text="관련 검색",
                    command=self.open_related_search_dialog,
                ),
                ttk.Button(
                    self.detail_header,
                    text="로그 보기 전용",
                    command=self.activate_log_view_layout,
                ),
                ttk.Button(
                    self.detail_header,
                    text="검색 화면",
                    command=self.activate_search_view_mode,
                ),
                ttk.Button(
                    self.detail_header,
                    text="기본 레이아웃",
                    command=self.restore_default_layout,
                ),
            ]
        )
        self._register_responsive_flow(
            self.detail_header, detail_items, gap=5, stretch_index=0
        )
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
        status_frame.grid(row=5, column=0, sticky="ew")
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

    def _register_responsive_flow(
        self,
        frame,
        widgets: list[object],
        horizontal_padding: int = 0,
        gap: int = 6,
        stretch_index: int | None = None,
    ) -> None:
        items = tuple(widgets)
        self._responsive_flows[frame] = {
            "widgets": items,
            "horizontal_padding": horizontal_padding,
            "gap": gap,
            "stretch_index": stretch_index,
            "layout_signature": None,
        }
        for column, widget in enumerate(items):
            widget.grid(row=0, column=column, padx=(0, gap), sticky="w")
        frame.bind(
            "<Configure>",
            lambda event, target=frame: self._layout_responsive_flow(target, event.width),
            add="+",
        )
        self.root.after_idle(lambda target=frame: self._layout_responsive_flow(target))

    def _layout_responsive_flow(self, frame, width: int | None = None) -> None:
        flow = self._responsive_flows.get(frame)
        if flow is None:
            return
        layout_responsive_flow(frame, flow, width)

    def toggle_options_panel(self, save: bool = True) -> None:
        if self.options_expanded_var.get():
            self.options_frame.grid()
        else:
            self.options_frame.grid_remove()
        if save:
            self.settings["options_panel_expanded"] = self.options_expanded_var.get()
            self._save_settings()

    def _load_settings(self) -> dict:
        if not APP_CONFIG_PATH.exists():
            return {}
        for encoding in ("utf-8-sig", "utf-8", "cp949"):
            try:
                data = json.loads(APP_CONFIG_PATH.read_text(encoding=encoding))
                if isinstance(data, dict):
                    return data
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
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
        saved_order = self.settings.get("column_order")
        visible_columns = self.settings.get("visible_columns")
        order = (
            [column for column in saved_order if column in COLUMNS]
            if isinstance(saved_order, list)
            else [column for column in visible_columns if column in COLUMNS]
            if isinstance(visible_columns, list)
            else list(COLUMNS)
        )
        for column in COLUMNS:
            if column not in order:
                if column == "time_delta" and "time" in order:
                    order.insert(order.index("time") + 1, column)
                else:
                    order.append(column)

        visibility = self.settings.get("column_visibility")
        if isinstance(visibility, dict):
            visible = [
                column
                for column in order
                if bool(visibility.get(column, True))
            ]
            return visible or ["message"]

        if not isinstance(visible_columns, list):
            return list(COLUMNS)

        visible_set = {column for column in visible_columns if column in COLUMNS}
        visible = [column for column in order if column in visible_set]
        # Bookmark/memo are newer columns; show them by default during migration.
        for new_column in reversed(("bookmark", "memo")):
            if new_column not in visible:
                visible.insert(0, new_column)
        return visible or ["message"]

    def _save_settings(self) -> None:
        self.settings["visible_columns"] = self.visible_columns
        self.settings["column_order"] = self._column_order_for_save()
        self.settings["column_visibility"] = {
            column: column in self.visible_columns for column in COLUMNS
        }
        self.settings["exclude_s6f11_enabled"] = self.exclude_s6f11_var.get()
        self.settings["exclude_s6f11_ceid_items"] = self.exclude_ceid_items
        self.settings["exclude_s6f11_ceid_ranges"] = self._exclude_ceid_legacy_text()
        self.settings["search_presets"] = self.search_presets
        self.settings["bookmarks"] = self.bookmarks
        self.settings["bookmark_only_filter"] = self.bookmark_only_var.get()
        self.settings["always_include_bookmarks"] = (
            self.always_include_bookmarks_var.get()
        )
        self.settings["bookmark_timeline_visible"] = (
            self.bookmark_timeline_visible_var.get()
        )
        self.settings["stats_panel_visible"] = self.stats_panel_visible_var.get()
        self.settings["context_rows"] = self.context_rows_var.get()
        self.settings["theme"] = self.theme_var.get()
        self.settings["detail_header_enabled"] = self.detail_header_var.get()
        self.settings["compare_mode_enabled"] = self.compare_mode_var.get()
        self.settings["flow_highlight_enabled"] = self.flow_highlight_var.get()
        self.settings["options_panel_expanded"] = self.options_expanded_var.get()
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
            encoding="utf-8-sig",
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
        self.root.option_add("*Menu.selectColor", colors["text"])
        self.root.option_add("*insertBackground", colors["text"])
        self.root.option_add("*Entry.insertBackground", colors["text"])

        style.configure(".", background=colors["bg"], foreground=colors["text"])
        style.configure("TFrame", background=colors["bg"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["text"])
        style.configure("TButton", background=colors["panel"], foreground=colors["text"])
        style.map(
            "TButton",
            background=[("active", colors["select_bg"])],
            foreground=[("active", colors["select_fg"])],
        )
        style.configure("TCheckbutton", background=colors["bg"], foreground=colors["text"])
        style.map("TCheckbutton", background=[("active", colors["bg"])])
        style.configure("TMenubutton", background=colors["panel"], foreground=colors["text"])
        style.map(
            "TMenubutton",
            background=[("active", colors["select_bg"])],
            foreground=[("active", colors["select_fg"])],
        )
        style.configure(
            "TEntry",
            fieldbackground=colors["field"],
            foreground=colors["text"],
            insertcolor=colors["text"],
            bordercolor=colors["border"],
        )
        style.map(
            "TEntry",
            fieldbackground=[("focus", colors["field"]), ("active", colors["field"])],
            foreground=[("focus", colors["text"]), ("active", colors["text"])],
        )
        style.configure(
            "TCombobox",
            background=colors["field"],
            fieldbackground=colors["field"],
            foreground=colors["text"],
            selectbackground=colors["field"],
            selectforeground=colors["text"],
            arrowcolor=colors["text"],
            bordercolor=colors["border"],
        )
        style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", colors["field"]),
                ("disabled", colors["panel"]),
            ],
            foreground=[
                ("readonly", colors["text"]),
                ("disabled", colors["muted"]),
            ],
            selectbackground=[
                ("readonly", colors["field"]),
            ],
            selectforeground=[
                ("readonly", colors["text"]),
            ],
            background=[
                ("readonly", colors["field"]),
                ("active", colors["field"]),
                ("focus", colors["field"]),
            ],
            arrowcolor=[
                ("readonly", colors["text"]),
                ("active", colors["text"]),
                ("focus", colors["text"]),
            ],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=colors["field"],
            foreground=colors["text"],
            insertcolor=colors["text"],
        )
        style.configure(
            "TNotebook",
            background=colors["bg"],
            bordercolor=colors["border"],
            tabmargins=(2, 2, 2, 0),
        )
        style.configure(
            "TNotebook.Tab",
            background=colors["panel"],
            foreground=colors["text"],
            bordercolor=colors["border"],
            padding=(10, 5),
        )
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", colors["field"]),
                ("active", colors["select_bg"]),
            ],
            foreground=[
                ("selected", colors["text"]),
                ("active", colors["select_fg"]),
            ],
        )
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
            "Treeview.Heading",
            background=[("active", colors["panel"])],
            foreground=[("active", colors["text"])],
        )
        style.map(
            "Treeview",
            background=[("selected", colors["select_bg"]), ("active", colors["tree_bg"])],
            foreground=[("selected", colors["select_fg"]), ("active", colors["text"])],
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
        for menu_name in (
            "column_menu",
            "preset_menu",
            "sxfy_menu",
            "time_filter_menu",
            "result_context_menu",
        ):
            if hasattr(self, menu_name):
                menu = getattr(self, menu_name)
                menu.configure(
                    bg=colors["panel"],
                    fg=colors["text"],
                    activebackground=colors["select_bg"],
                    activeforeground=colors["select_fg"],
                    selectcolor=colors["text"],
                )
        self._apply_input_cursor_theme(self.root, colors)
        if hasattr(self, "tree"):
            self.tree.tag_configure("bookmarked", background=colors["tree_alt"])
        if hasattr(self, "all_logs_tree"):
            self.all_logs_tree.tag_configure(
                "bookmarked", background=colors["tree_alt"]
            )
        if hasattr(self, "splitter_grip"):
            self.splitter_grip.configure(background=colors["grip_bg"])
            self._draw_splitter_grip()
        if hasattr(self, "detail_pane_container"):
            self._refresh_detail_text_theme(self.detail_pane_container, colors)
        if hasattr(self, "stats_text"):
            self.stats_text.configure(
                bg=colors["detail_bg"],
                fg=colors["detail_fg"],
                selectbackground=colors["select_bg"],
                selectforeground=colors["select_fg"],
                highlightbackground=colors["border"],
                insertbackground=colors["detail_fg"],
            )
        if hasattr(self, "keyword_tag_text"):
            self._refresh_keyword_listboxes()
        if save:
            self._save_settings()


    def _apply_input_cursor_theme(self, widget, colors: dict[str, str]) -> None:
        for child in widget.winfo_children():
            for option, value in (
                ("insertbackground", colors["text"]),
                ("insertcolor", colors["text"]),
            ):
                try:
                    child.configure(**{option: value})
                except Exception:
                    pass
            self._apply_input_cursor_theme(child, colors)

    def _refresh_detail_text_theme(self, widget, colors: dict[str, str]) -> None:
        for child in widget.winfo_children():
            if isinstance(child, Text):
                self._configure_detail_text_theme(child, colors)
            self._refresh_detail_text_theme(child, colors)

    def _configure_detail_text_theme(self, text: Text, colors: dict[str, str]) -> None:
        text.configure(
            bg=colors["detail_bg"],
            fg=colors["detail_fg"],
            insertbackground=colors["detail_fg"],
            selectbackground=colors["select_bg"],
            selectforeground=colors["select_fg"],
        )
        text.tag_configure(
            "match",
            background=colors["highlight_bg"],
            foreground=colors["highlight_fg"],
        )
        text.tag_configure(
            "flow_match",
            background=colors["flow_highlight_bg"],
            foreground=colors["flow_highlight_fg"],
        )
        text.tag_configure("selected_log", background=colors["select_bg"])
        text.tag_configure("replace", background=colors["compare_change_bg"])
        text.tag_configure("delete", background=colors["compare_delete_bg"])
        text.tag_configure("insert", background=colors["compare_insert_bg"])
        text.tag_configure(
            "char_diff",
            foreground=colors["compare_char_diff_fg"],
            underline=True,
        )

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

    def _build_time_filter_menu(self) -> None:
        self.time_filter_menu.delete(0, "end")
        for label, seconds in TIME_FILTER_WINDOWS:
            self.time_filter_menu.add_command(
                label=label,
                command=lambda value=seconds: self.apply_time_window_filter(value),
            )
        self.time_filter_menu.add_separator()
        self.time_filter_menu.add_command(
            label="이 시각 이후",
            command=lambda: self.apply_time_direction_filter("after"),
        )
        self.time_filter_menu.add_command(
            label="이 시각 이전",
            command=lambda: self.apply_time_direction_filter("before"),
        )
        self.time_filter_menu.add_separator()
        self.time_filter_menu.add_command(
            label="직접 시간 지정...", command=self.open_custom_time_filter_dialog
        )
        self.time_filter_menu.add_command(label="시간 필터 해제", command=self.clear_time_filter)

    def _update_sxfy_filters(self, entries: list[LogEntry], select_all: bool = True) -> None:
        types = sorted(
            {
                _sxfy_label(match)
                for entry in entries
                for match in SXFy_RE.finditer(entry.message)
            }
        )
        self.sxfy_types = types
        self.sxfy_filter_vars = {
            message_type: BooleanVar(value=select_all)
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

    def on_search_option_changed(self) -> None:
        self._mark_keyword_filters_pending("검색 옵션 변경됨.")

    def apply_filters_shortcut(self, _event=None) -> str:
        self.apply_filters()
        return "break"

    def _disable_bookmark_only_for_analysis(self) -> None:
        if not self.bookmark_only_var.get():
            return
        self.bookmark_only_var.set(False)
        self._pending_filter_restore_key = None
        self._save_settings()
    def on_bookmark_only_changed(self) -> None:
        self._pending_filter_restore_key = (
            self._selected_single_entry_key()
            if not self.bookmark_only_var.get()
            else None
        )
        self._save_settings()
        self.apply_filters()

    def on_always_include_bookmarks_changed(self) -> None:
        self._save_settings()
        self.apply_filters()

    def on_bookmark_timeline_visibility_changed(self) -> None:
        self._apply_bookmark_timeline_visibility(save=True)
        state = "표시" if self.bookmark_timeline_visible_var.get() else "숨김"
        self.status_var.set(f"북마크 타임라인 {state} 설정 저장됨: {APP_CONFIG_PATH}")

    def on_stats_panel_visibility_changed(self) -> None:
        self._apply_stats_panel_visibility(save=True)
        state = "표시" if self.stats_panel_visible_var.get() else "숨김"
        self.status_var.set(f"통계 패널 {state} 설정 저장됨: {APP_CONFIG_PATH}")

    def _apply_bookmark_timeline_visibility(self, save: bool = True) -> None:
        if not hasattr(self, "bookmark_timeline_frame"):
            return
        if self.bookmark_timeline_visible_var.get():
            self.bookmark_timeline_frame.grid()
            self._refresh_bookmark_timeline()
        else:
            self.bookmark_timeline_frame.grid_remove()
        self._sync_result_sidebar_visibility()
        if save:
            self._save_settings()

    def _apply_stats_panel_visibility(self, save: bool = True) -> None:
        if not hasattr(self, "stats_frame"):
            return
        if self.stats_panel_visible_var.get():
            self.stats_frame.grid()
            self._refresh_stats_panel()
        else:
            self.stats_frame.grid_remove()
        self._sync_result_sidebar_visibility()
        if save:
            self._save_settings()

    def _sync_result_sidebar_visibility(self) -> None:
        if not hasattr(self, "result_area_pane") or not hasattr(
            self, "result_sidebar_frame"
        ):
            return
        panes = tuple(str(pane) for pane in self.result_area_pane.panes())
        sidebar = str(self.result_sidebar_frame)
        should_show = (
            self.bookmark_timeline_visible_var.get()
            or self.stats_panel_visible_var.get()
        )
        if should_show and sidebar not in panes:
            self.result_area_pane.add(self.result_sidebar_frame, weight=1)
        elif not should_show and sidebar in panes:
            self.result_area_pane.forget(self.result_sidebar_frame)

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
        ordered_columns = self._column_order_for_save()
        selected = [
            column
            for column in ordered_columns
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
        if hasattr(self, "all_logs_tree"):
            self.all_logs_tree.configure(displaycolumns=self.visible_columns)
        if save:
            self._save_settings()
            self.status_var.set(f"컬럼 설정 저장됨: {APP_CONFIG_PATH}")
            self.show_selected_detail()

    def _column_order_for_save(self) -> list[str]:
        order = list(self.visible_columns)
        order.extend(column for column in COLUMNS if column not in order)
        return order

    def _tree_column_at(self, x: int, y: int) -> str | None:
        if self.tree.identify_region(x, y) != "heading":
            return None
        column_ref = self.tree.identify_column(x)
        if not column_ref or not column_ref.startswith("#"):
            return None
        try:
            display_index = int(column_ref[1:]) - 1
        except ValueError:
            return None
        if display_index < 0 or display_index >= len(self.visible_columns):
            return None
        return self.visible_columns[display_index]

    def _set_tree_cursor(self, cursor: str) -> None:
        try:
            self.tree.configure(cursor=cursor)
        except Exception:
            fallback = "fleur" if cursor else ""
            try:
                self.tree.configure(cursor=fallback)
            except Exception:
                self.tree.configure(cursor="hand2" if cursor else "")

    def _move_visible_column(self, source: str, target: str, save: bool = False) -> bool:
        if source == target:
            return False
        if source not in self.visible_columns or target not in self.visible_columns:
            return False
        old_order = list(self.visible_columns)
        source_index = old_order.index(source)
        target_index = old_order.index(target)
        reordered = list(old_order)
        reordered.remove(source)
        insert_index = target_index if source_index > target_index else target_index
        insert_index = max(0, min(insert_index, len(reordered)))
        reordered.insert(insert_index, source)
        if reordered == old_order:
            return False
        self.visible_columns = reordered
        for column in COLUMNS:
            self.column_visible_vars[column].set(column in self.visible_columns)
        self._apply_visible_columns(save=save)
        return True

    def _on_tree_button_press(self, event) -> str | None:
        if self._is_control_click(event):
            return self._on_tree_control_click(event)
        self._column_drag_source = self._tree_column_at(event.x, event.y)
        if self._column_drag_source:
            self._set_tree_cursor("hand1")
        return None

    def _on_tree_drag_motion(self, event) -> str | None:
        source = self._column_drag_source
        if not source:
            return None
        self._set_tree_cursor("hand1")
        target = self._tree_column_at(event.x, event.y)
        if target and self._move_visible_column(source, target, save=False):
            self.status_var.set("컬럼 순서 변경 중...")
        return "break"

    def _on_tree_button_release(self, event) -> None:
        source = self._column_drag_source
        self._column_drag_source = None
        target = self._tree_column_at(event.x, event.y)
        if not source:
            self._on_tree_motion(event)
            return
        if target:
            self._move_visible_column(source, target, save=True)
        else:
            self._apply_visible_columns(save=True)
        self.status_var.set("컬럼 순서가 저장되었습니다.")
        self._on_tree_motion(event)

    def _on_tree_motion(self, event) -> None:
        if self._column_drag_source:
            self._set_tree_cursor("hand1")
        elif self._tree_column_at(event.x, event.y):
            self._set_tree_cursor("hand2")
        else:
            self._set_tree_cursor("")

    def _on_tree_leave(self, _event) -> None:
        if not self._column_drag_source:
            self._set_tree_cursor("")

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
        panes = tuple(str(pane) for pane in self.content_pane.panes())
        try:
            detail_index = panes.index(str(self.detail_frame))
        except ValueError:
            return "break"
        sash_index = detail_index - 1
        if sash_index < 0:
            return "break"
        y = event.y_root - self.content_pane.winfo_rooty()
        min_y = 120
        max_y = max(min_y, self.content_pane.winfo_height() - 120)
        self.content_pane.sashpos(sash_index, max(min_y, min(y, max_y)))
        return "break"

    def activate_log_view_layout(self) -> None:
        if self.log_view_layout_active:
            return
        self.deactivate_search_view_mode()
        panes = tuple(str(pane) for pane in self.content_pane.panes())
        if str(self.table_frame) in panes:
            self.content_pane.forget(self.table_frame)
        if hasattr(self, "roundtrip_frame") and str(self.roundtrip_frame) in panes:
            self.content_pane.forget(self.roundtrip_frame)
        for frame in self._top_control_frames():
            frame.grid_remove()
        self.content_pane.grid_configure(row=0, rowspan=5, padx=10, pady=(0, 8))
        for row in range(0, 5):
            self.root.rowconfigure(row, weight=0)
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(5, weight=0)
        self.log_view_layout_active = True
        self.status_var.set("로그 보기 전용 레이아웃으로 전환했습니다.")

    def activate_search_view_mode(self) -> None:
        if self.log_view_layout_active:
            self.restore_default_layout()
        panes = tuple(str(pane) for pane in self.search_view_pane.panes())
        if str(self.all_logs_frame) not in panes:
            self.search_view_pane.insert(0, self.all_logs_frame, weight=1)
        self.search_view_mode_active = True
        self.refresh_all_logs_table()
        self.root.after_idle(self._position_search_view_sash)
        self.status_var.set(
            "검색 화면 모드: 오른쪽 결과를 선택하면 왼쪽 전체 로그로 이동합니다."
        )

    def deactivate_search_view_mode(self) -> None:
        if not hasattr(self, "search_view_pane"):
            self.search_view_mode_active = False
            return
        panes = tuple(str(pane) for pane in self.search_view_pane.panes())
        if str(self.all_logs_frame) in panes:
            self.search_view_pane.forget(self.all_logs_frame)
        self.search_view_mode_active = False

    def _position_search_view_sash(self) -> None:
        if not self.search_view_mode_active:
            return
        if len(self.search_view_pane.panes()) < 2:
            return
        width = self.search_view_pane.winfo_width()
        if width > 0:
            self.search_view_pane.sashpos(0, max(280, width // 2))

    def restore_default_layout(self) -> None:
        self.deactivate_search_view_mode()
        self.content_pane.grid_configure(row=4, rowspan=1, padx=10, pady=(0, 8))
        for row in range(0, 5):
            self.root.rowconfigure(row, weight=0)
        self.root.rowconfigure(4, weight=1)
        for frame in (self.toolbar_frame, self.quick_search_frame, self.drop_frame):
            frame.grid()
        self.toggle_options_panel(save=False)
        panes = tuple(str(pane) for pane in self.content_pane.panes())
        if str(self.table_frame) not in panes:
            self.content_pane.insert(0, self.table_frame, weight=4)
        panes = tuple(str(pane) for pane in self.content_pane.panes())
        if (
            CARRIER_ROUNDTRIP_TIMELINE_ENABLED
            and hasattr(self, "roundtrip_frame")
            and str(self.roundtrip_frame) not in panes
        ):
            insert_index = 1 if str(self.table_frame) in panes else 0
            self.content_pane.insert(insert_index, self.roundtrip_frame, weight=1)
        if str(self.detail_frame) not in tuple(str(pane) for pane in self.content_pane.panes()):
            self.content_pane.add(self.detail_frame, weight=1)
        self.log_view_layout_active = False
        self.status_var.set("기본 레이아웃으로 복귀했습니다.")

    def _top_control_frames(self) -> tuple[ttk.Frame, ...]:
        return (
            self.toolbar_frame,
            self.quick_search_frame,
            self.options_frame,
            self.drop_frame,
        )

    def _focus_result_table(self) -> None:
        try:
            self.tree.focus_set()
        except Exception:
            pass

    def _entry_key(self, entry: LogEntry) -> str:
        return f"{entry.source_file}|{entry.line_no}|{entry.display_time}"

    def _entry_index_for_key(
        self, entries: list[LogEntry], entry_key: str
    ) -> int | None:
        for index, entry in enumerate(entries):
            if self._entry_key(entry) == entry_key:
                return index
        return None

    def _full_entry_index(self, entry: LogEntry) -> int | None:
        index = entry.timeline_index
        if (
            index is not None
            and 0 <= index < len(self.entries)
            and self.entries[index] is entry
        ):
            return index
        return self._entry_index_for_key(self.entries, self._entry_key(entry))

    def refresh_all_logs_table(
        self,
        focus_index: int | None = None,
    ) -> None:
        if not hasattr(self, "all_logs_tree"):
            return
        if focus_index is not None:
            focused_item = str(focus_index)
            if self.all_logs_tree.exists(focused_item):
                self.all_logs_tree.selection_set(focused_item)
                self.all_logs_tree.focus(focused_item)
                self.all_logs_tree.see(focused_item)
                return
        children = self.all_logs_tree.get_children()
        if children:
            self.all_logs_tree.delete(*children)
        total_count = len(self.entries)
        window_size = min(
            max(1, self.display_rows_var.get()),
            MAX_ALL_LOGS_WINDOW_ROWS,
            total_count,
        )
        window_start = 0
        if focus_index is not None and window_size:
            window_start = max(0, focus_index - window_size // 2)
            window_start = min(window_start, total_count - window_size)
        window_end = window_start + window_size
        for index in range(window_start, window_end):
            entry = self.entries[index]
            bookmarked = self._is_bookmarked(entry)
            time_delta = ""
            if index > 0:
                time_delta = self._format_time_delta(
                    entry.timestamp - self.entries[index - 1].timestamp
                )
            self.all_logs_tree.insert(
                "",
                "end",
                iid=str(index),
                values=_entry_to_values(
                    entry,
                    self.matched_keywords_by_entry.get(id(entry), ""),
                    bookmarked,
                    self._entry_memo(entry),
                    time_delta,
                ),
                tags=("bookmarked",) if bookmarked else (),
            )
        if window_size:
            window_description = (
                f", 표시 {window_size:,}건, 구간 "
                f"#{window_start + 1:,}~#{window_end:,}"
            )
        else:
            window_description = ""
        self.all_logs_title_var.set(
            f"전체 로그 ({total_count:,}건{window_description})"
        )
        if focus_index is None:
            return
        item = str(focus_index)
        if self.all_logs_tree.exists(item):
            self.all_logs_tree.selection_set(item)
            self.all_logs_tree.focus(item)
            self.all_logs_tree.see(item)

    def on_filtered_result_selected_in_search_mode(self, _event=None) -> None:
        if not self.search_view_mode_active:
            return
        index = self._first_selected_display_index()
        if index is None or index >= len(self.filtered_entries):
            return
        entry = self.filtered_entries[index]
        full_index = self._full_entry_index(entry)
        if full_index is None:
            return
        self.refresh_all_logs_table(focus_index=full_index)
        self.status_var.set(
            f"전체 로그 이동: #{full_index + 1} "
            f"{entry.display_time} {entry.source_file}:{entry.line_no}"
        )

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

    def _first_selected_display_index(self) -> int | None:
        indices = self._selected_display_indices()
        return indices[0] if indices else None

    def _filtered_index_for_entry_key(self, entry_key: str) -> int | None:
        for index, entry in enumerate(self.filtered_entries):
            if self._entry_key(entry) == entry_key:
                return index
        return None

    def _select_filtered_entry_by_key(self, entry_key: str) -> bool:
        index = self._filtered_index_for_entry_key(entry_key)
        if index is None:
            return False
        item = str(index)
        if not self.tree.exists(item):
            return False
        self.tree.selection_set(item)
        self.tree.focus(item)
        self.tree.see(item)
        self.show_selected_detail()
        return True

    def _selected_single_entry_key(self) -> str | None:
        indices = self._selected_display_indices()
        if len(indices) != 1:
            return None
        return self._entry_key(self.filtered_entries[indices[0]])

    def select_all_filtered_logs(self, _event=None) -> str:
        result_count = len(self.filtered_entries)
        if result_count == 0:
            self.status_var.set("선택할 검색 결과가 없습니다.")
            return "break"
        if len(self.tree.get_children()) < result_count:
            self.refresh_table(keep_detail=True, row_limit_override=result_count)
        items = self.tree.get_children()
        self.tree.selection_set(*items)
        if items:
            self.tree.focus(items[0])
            self.tree.see(items[0])
        self._focus_result_table()
        self.status_var.set(f"현재 검색 결과 {len(items):,}건을 모두 선택했습니다.")
        return "break"

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

    @staticmethod
    def _is_control_click(event) -> bool:
        return bool(getattr(event, "state", 0) & 0x0004)

    def _set_tree_selection(self, items: tuple[str, ...]) -> None:
        current = self.tree.selection()
        if current:
            self.tree.selection_remove(*current)
        if items:
            self.tree.selection_add(*items)

    def _restore_tree_selection_after_control_click(
        self, item: str, selected_items: tuple[str, ...]
    ) -> None:
        self._set_tree_selection(selected_items)
        self.tree.focus(item)
        self.tree.see(item)
        self.show_selected_detail()

    def _on_tree_control_click(self, event) -> str | None:
        if not self.bookmark_only_var.get():
            return None
        if self.tree.identify_region(event.x, event.y) not in {"cell", "tree"}:
            return None
        item = self.tree.identify_row(event.y)
        if not item:
            return "break"
        selected = set(self.tree.selection())
        if item in selected:
            selected.remove(item)
        else:
            selected.add(item)
        selected_items = tuple(sorted(selected, key=int))
        self._restore_tree_selection_after_control_click(item, selected_items)
        self.root.after_idle(
            lambda item=item, selected_items=selected_items: self._restore_tree_selection_after_control_click(
                item, selected_items
            )
        )
        return "break"

    def _on_tree_right_click(self, event) -> str:
        item = self.tree.identify_row(event.y)
        if item:
            if item not in self.tree.selection():
                self.tree.selection_set(item)
                self.show_selected_detail()
            self.tree.focus(item)
        selected = self._selected_display_indices()
        self.result_context_menu.entryconfigure(
            0, state="normal" if selected else "disabled"
        )
        try:
            self.result_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.result_context_menu.grab_release()
        return "break"

    def copy_selected_logs_to_clipboard(self) -> None:
        indices = self._selected_display_indices()
        if not indices:
            self.status_var.set("복사할 로그가 선택되지 않았습니다.")
            return
        entries = [self.filtered_entries[index] for index in indices]
        text = self._format_entries_for_clipboard(entries)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(f"선택 로그 {len(entries):,}건을 클립보드로 복사했습니다.")

    @staticmethod
    def _format_entries_for_clipboard(entries: list[LogEntry]) -> str:
        return format_entries_for_clipboard(entries)

    @staticmethod
    def _format_entry_for_clipboard(entry: LogEntry) -> str:
        return format_entry_for_clipboard(entry)

    def _selected_time_anchor(self) -> tuple[LogEntry, int] | None:
        indices = self._selected_display_indices()
        if len(indices) != 1:
            messagebox.showinfo("시간 범위 필터", "기준으로 사용할 로그 1개를 선택하세요.")
            return None
        index = indices[0]
        return self.filtered_entries[index], index

    def apply_time_window_filter(self, seconds: int) -> None:
        anchor = self._selected_time_anchor()
        if anchor is None:
            return
        entry, _index = anchor
        window = timedelta(seconds=seconds)
        self.time_filter_start = entry.timestamp - window
        self.time_filter_end = entry.timestamp + window
        self._update_time_filter_summary()
        self.apply_filters()

    def apply_time_direction_filter(self, direction: str) -> None:
        anchor = self._selected_time_anchor()
        if anchor is None:
            return
        entry, _index = anchor
        if direction == "after":
            self.time_filter_start = entry.timestamp
            self.time_filter_end = None
        else:
            self.time_filter_start = None
            self.time_filter_end = entry.timestamp
        self._update_time_filter_summary()
        self.apply_filters()

    def open_custom_time_filter_dialog(self) -> None:
        window = Toplevel(self.root)
        window.title("직접 시간 지정")
        window.transient(self.root)
        window.grab_set()
        window.resizable(False, False)
        window.columnconfigure(1, weight=1)

        default_start, default_end = self._default_time_filter_inputs()
        start_var = StringVar(value=default_start)
        end_var = StringVar(value=default_end)
        status_var = StringVar(value="형식: YYYY-MM-DD HH:MM:SS.fff 또는 HH:MM:SS")

        ttk.Label(window, text="시작 시간").grid(
            row=0, column=0, sticky="w", padx=(12, 6), pady=(12, 4)
        )
        start_entry = ttk.Entry(window, textvariable=start_var, width=30)
        start_entry.grid(row=0, column=1, sticky="ew", padx=(0, 12), pady=(12, 4))
        ttk.Label(window, text="종료 시간").grid(
            row=1, column=0, sticky="w", padx=(12, 6), pady=4
        )
        end_entry = ttk.Entry(window, textvariable=end_var, width=30)
        end_entry.grid(row=1, column=1, sticky="ew", padx=(0, 12), pady=4)
        ttk.Label(window, textvariable=status_var).grid(
            row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(4, 8)
        )
        button_frame = ttk.Frame(window)
        button_frame.grid(row=3, column=0, columnspan=2, sticky="e", padx=12, pady=(0, 12))

        def apply_custom_filter() -> None:
            try:
                start, end = self._parse_custom_time_filter_inputs(
                    start_var.get(), end_var.get()
                )
            except ValueError as exc:
                status_var.set(str(exc))
                return
            self.time_filter_start = start
            self.time_filter_end = end
            self._update_time_filter_summary()
            self.apply_filters()
            window.destroy()

        ttk.Button(button_frame, text="적용", command=apply_custom_filter).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(
            button_frame,
            text="해제",
            command=lambda: (window.destroy(), self.clear_time_filter()),
        ).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(button_frame, text="닫기", command=window.destroy).grid(row=0, column=2)
        start_entry.bind("<Return>", lambda _event: apply_custom_filter())
        end_entry.bind("<Return>", lambda _event: apply_custom_filter())
        start_entry.focus_set()

    def _default_time_filter_inputs(self) -> tuple[str, str]:
        if self.time_filter_start or self.time_filter_end:
            return (
                self._format_time_filter_input(self.time_filter_start),
                self._format_time_filter_input(self.time_filter_end),
            )
        if self.entries:
            return (
                self._format_time_filter_input(self.entries[0].timestamp),
                self._format_time_filter_input(self.entries[-1].timestamp),
            )
        return "", ""

    @staticmethod
    def _format_time_filter_input(value: datetime | None) -> str:
        return format_time_filter_input(value)

    def _parse_custom_time_filter_inputs(
        self, start_text: str, end_text: str
    ) -> tuple[datetime | None, datetime | None]:
        return parse_custom_time_filter_inputs(
            start_text, end_text, self._default_time_filter_date()
        )

    def _default_time_filter_date(self):
        if self.entries:
            return self.entries[0].timestamp.date()
        return datetime.now().date()

    @staticmethod
    def _parse_time_filter_input(
        text: str, default_date
    ) -> tuple[datetime | None, bool]:
        return parse_time_filter_input(text, default_date)

    def clear_time_filter(self) -> None:
        self.time_filter_start = None
        self.time_filter_end = None
        self._update_time_filter_summary()
        self.apply_filters()

    def _update_time_filter_summary(self) -> None:
        if self.time_filter_start is None and self.time_filter_end is None:
            self.time_filter_summary_var.set("시간 필터 없음")
            return
        start = self._format_time_filter_summary_value(self.time_filter_start, "처음")
        end = self._format_time_filter_summary_value(self.time_filter_end, "끝")
        self.time_filter_summary_var.set(f"{start} ~ {end}")

    @staticmethod
    def _format_time_filter_summary_value(value: datetime | None, empty_label: str) -> str:
        if value is None:
            return empty_label
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _time_delta_for_index(self, index: int) -> str:
        if index <= 0 or index >= len(self.filtered_entries):
            return ""
        previous = self.filtered_entries[index - 1]
        current = self.filtered_entries[index]
        return self._format_time_delta(current.timestamp - previous.timestamp)

    @staticmethod
    def _format_time_delta(delta) -> str:
        return format_time_delta(delta)

    def on_context_rows_changed(self) -> None:
        self._save_settings()
        self.refresh_selected_detail()

    def on_detail_header_changed(self) -> None:
        self._save_settings()
        self.refresh_selected_detail()
        state = "표시" if self.detail_header_var.get() else "숨김"
        self.status_var.set(f"상세 로그 헤더 {state} 설정 저장됨: {APP_CONFIG_PATH}")

    def on_compare_mode_changed(self) -> None:
        self._save_settings()
        self.show_selected_detail()
        state = "사용" if self.compare_mode_var.get() else "해제"
        self.status_var.set(f"로그 비교 보기 {state} 설정 저장됨: {APP_CONFIG_PATH}")

    def on_flow_highlight_changed(self) -> None:
        self._save_settings()
        self.show_selected_detail()
        state = "사용" if self.flow_highlight_var.get() else "해제"
        self.status_var.set(f"ID 흐름 강조 {state} 설정 저장됨: {APP_CONFIG_PATH}")

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
        self.refresh_selected_detail()
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
        if self.bookmark_only_var.get() or self.always_include_bookmarks_var.get():
            self.apply_filters()
            self.root.after_idle(self._focus_result_table)
            return
        self.refresh_table(keep_detail=True)
        for index in indices:
            if str(index) in self.tree.get_children():
                self.tree.selection_add(str(index))
        self.show_selected_detail()
        self._refresh_bookmark_timeline()
        self._focus_result_table()

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
        if self.bookmark_only_var.get() or self.always_include_bookmarks_var.get():
            self.apply_filters()
            self.root.after_idle(self._focus_result_table)
            return
        self.refresh_table(keep_detail=True)
        self.tree.selection_set(str(indices[0]))
        self.show_selected_detail()
        self._refresh_bookmark_timeline()

    def _refresh_stats_panel(self) -> None:
        if not hasattr(self, "stats_text") or not self.stats_panel_visible_var.get():
            return
        entries = self.filtered_entries
        type_counts = Counter(entry.log_type.value for entry in entries)
        sxfy_counts = Counter(
            sxfy
            for entry in entries
            for sxfy in [self._entry_sxfy_type(entry)]
            if sxfy
        )
        ceid_counts = Counter(str(entry.ceid) for entry in entries if entry.ceid is not None)
        event_counts = Counter(entry.event_name for entry in entries if entry.event_name)
        bookmarked_count = sum(1 for entry in entries if self._is_bookmarked(entry))
        alarm_count = sum(1 for entry in entries if is_alarm_entry(entry))

        lines = [
            f"총 {len(entries):,}건",
            f"MMI {type_counts.get('MMI', 0):,} / SECS {type_counts.get('SECS', 0):,}",
            f"북마크 {bookmarked_count:,} / Alarm {alarm_count:,}",
            "",
            "SxFy TOP",
            *self._format_top_counts(sxfy_counts),
            "",
            "CEID TOP",
            *self._format_top_counts(ceid_counts),
            "",
            "이벤트명 TOP",
            *self._format_top_counts(event_counts),
        ]
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("1.0", "\n".join(lines))
        self.stats_text.configure(state="disabled")

    @staticmethod
    def _format_top_counts(counter: Counter, limit: int = 10) -> list[str]:
        if not counter:
            return ["  -"]
        return [f"  {name}: {count:,}" for name, count in counter.most_common(limit)]

    def _refresh_bookmark_timeline(self) -> None:
        if not hasattr(self, "bookmark_timeline"):
            return
        previous_updating = self._bookmark_timeline_updating
        self._bookmark_timeline_updating = True
        try:
            children = self.bookmark_timeline.get_children()
            if children:
                self.bookmark_timeline.delete(*children)
            rows = self.filtered_entries[: max(1, self.display_rows_var.get())]
            count = 0
            for index, entry in enumerate(rows):
                if not self._is_bookmarked(entry):
                    continue
                log_type = entry.log_type.value
                sxfy = self._entry_sxfy_type(entry)
                if sxfy:
                    log_type = f"{log_type} {sxfy}"
                self.bookmark_timeline.insert(
                    "",
                    "end",
                    iid=str(index),
                    values=(entry.display_time, log_type, self._entry_memo(entry)),
                )
                count += 1
            self.bookmark_timeline_title_var.set(f"북마크 타임라인 ({count})")
            self._sync_bookmark_timeline_selection()
        finally:
            self._bookmark_timeline_updating = previous_updating

    def on_bookmark_timeline_select(self, _event=None) -> None:
        if self._bookmark_timeline_updating or self._bookmark_timeline_jump_running:
            return
        selected = self.bookmark_timeline.selection()
        if not selected:
            return
        item = selected[0]
        if item not in self.tree.get_children():
            return
        self._bookmark_timeline_jump_running = True
        try:
            if self.tree.selection() != (item,):
                self.tree.selection_set(item)
            self.tree.focus(item)
            self.tree.see(item)
            self.root.after_idle(lambda item=item: self._complete_bookmark_timeline_jump(item))
        except Exception:
            self._bookmark_timeline_jump_running = False
            raise

    def _complete_bookmark_timeline_jump(self, item: str) -> None:
        try:
            if item not in self.tree.get_children():
                return
            self.show_selected_detail()
            index = int(item)
            entry = self.filtered_entries[index]
            self.status_var.set(
                f"북마크 이동: #{index + 1} {entry.display_time} {entry.source_file}:{entry.line_no}"
            )
        finally:
            self._bookmark_timeline_jump_running = False

    def _sync_bookmark_timeline_selection(self) -> None:
        if not hasattr(self, "bookmark_timeline"):
            return
        index = self._first_selected_display_index()
        selected_item = str(index) if index is not None else ""
        current_items = set(self.bookmark_timeline.get_children())
        previous_updating = self._bookmark_timeline_updating
        self._bookmark_timeline_updating = True
        try:
            if selected_item and selected_item in current_items:
                if self.bookmark_timeline.selection() != (selected_item,):
                    self.bookmark_timeline.selection_set(selected_item)
                self.bookmark_timeline.focus(selected_item)
                self.bookmark_timeline.see(selected_item)
            else:
                selected = self.bookmark_timeline.selection()
                if selected:
                    self.bookmark_timeline.selection_remove(selected)
        finally:
            self._bookmark_timeline_updating = previous_updating

    def open_related_search_dialog(self) -> None:
        indices = self._selected_display_indices()
        if len(indices) != 1:
            messagebox.showinfo("관련 검색", "관련 검색할 로그 1개를 선택하세요.")
            return
        entry = self.filtered_entries[indices[0]]
        candidates = self._related_search_candidates(entry)
        if not candidates:
            messagebox.showinfo("관련 검색", "선택 로그에서 검색 후보를 찾지 못했습니다.")
            return

        window = Toplevel(self.root)
        window.title("선택 로그 관련 검색")
        window.geometry("520x420")
        window.minsize(460, 340)
        window.transient(self.root)
        window.grab_set()
        colors = THEMES.get(self.theme_var.get(), THEMES["light"])
        window.configure(bg=colors["bg"])
        window.columnconfigure(0, weight=1)
        window.rowconfigure(1, weight=1)

        ttk.Label(
            window,
            text="선택한 값을 포함 키워드로 추가하여 관련 로그를 검색합니다.",
            padding=(10, 10, 10, 4),
        ).grid(row=0, column=0, sticky="ew")

        list_frame = ttk.Frame(window, padding=(10, 0, 10, 8))
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        candidate_list = Listbox(list_frame, selectmode="extended", height=12)
        candidate_list.configure(
            bg=colors["field"],
            fg=colors["text"],
            selectbackground=colors["select_bg"],
            selectforeground=colors["select_fg"],
            highlightbackground=colors["border"],
        )
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=candidate_list.yview)
        candidate_list.configure(yscrollcommand=scroll.set)
        candidate_list.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        for label, keyword in candidates:
            candidate_list.insert("end", f"{label}: {keyword}")
        candidate_list.selection_set(0, "end")

        button_frame = ttk.Frame(window, padding=(10, 0, 10, 10))
        button_frame.grid(row=2, column=0, sticky="ew")
        button_frame.columnconfigure(0, weight=1)

        def selected_keywords() -> list[str]:
            return [candidates[index][1] for index in candidate_list.curselection()]

        def apply_related(mode: str) -> None:
            keywords = selected_keywords()
            if not keywords:
                messagebox.showinfo("관련 검색", "추가할 항목을 선택하세요.", parent=window)
                return
            added = self._add_related_keywords(mode, keywords)
            window.destroy()
            if added:
                self._mark_keyword_filters_pending(
                    f"관련 검색 키워드 {added}개 추가됨."
                )

        ttk.Button(
            button_frame, text="AND로 추가", command=lambda: apply_related("AND")
        ).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(
            button_frame, text="OR로 추가", command=lambda: apply_related("OR")
        ).grid(row=0, column=2, padx=(0, 6))
        ttk.Button(button_frame, text="취소", command=window.destroy).grid(
            row=0, column=3
        )

    def _add_related_keywords(self, mode: str, keywords: list[str]) -> int:
        added = 0
        normalized_mode = mode if mode in {"AND", "OR"} else "AND"
        for keyword in keywords:
            cleaned = keyword.strip()
            if not cleaned:
                continue
            item = (normalized_mode, cleaned)
            if item in self.keywords:
                continue
            self.keywords.append(item)
            added += 1
        self.selected_keyword_index = None
        self.keyword_var.set("")
        self._render_keyword_tags()
        return added

    def _related_search_candidates(self, entry: LogEntry) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []

        def add(label: str, keyword: str | None) -> None:
            if not keyword:
                return
            cleaned = keyword.strip().strip("\"'")
            if not cleaned:
                return
            if cleaned.upper() in {"(NULL)", "NULL", "NONE", "NO", "YES", "N/A"}:
                return
            item = (label, cleaned)
            if item not in candidates:
                candidates.append(item)

        message = entry.message
        sxfy = self._entry_sxfy_type(entry)
        add("SxFy", sxfy)
        if entry.ceid is not None:
            add("CEID", str(entry.ceid))
        add("이벤트명", entry.event_name)

        for object_name in (
            "CarrierObject",
            "SubstrateObject",
            "LoadPortObject",
            "ProcessJob",
            "ControlJob",
            "PortObject",
        ):
            if object_name.lower() in message.lower():
                add("객체", object_name)

        patterns: list[tuple[str, str]] = [
            ("Carrier ID", r"\b(?:CARRIER_ID|CARRIERID|Carrier\s*ID)\s*[:=]\s*([^,\s;]+)"),
            ("Substrate ID", r"\b(?:SubstID|SUBST_ID|SubstrateID|Substrate\s*ID|SUBSTRATE_ID)\s*[:=]\s*([^,\s;<>]+)"),
            ("Substrate ID", r"<(?:SubstID|SUBST_ID|SubstrateID|SUBSTRATE_ID)>\s*([^<]+)\s*</(?:SubstID|SUBST_ID|SubstrateID|SUBSTRATE_ID)>"),
            ("Acquired ID", r"\b(?:AcquiredID|Acquired\s*ID|ACQUIRED_ID)\s*[:=]\s*([^,\s;<>]+)"),
            ("Acquired ID", r"<(?:AcquiredID|ACQUIRED_ID)>\s*([^<]+)\s*</(?:AcquiredID|ACQUIRED_ID)>"),
            ("Port No", r"\b(?:PorNo|Port|PortNo|PORT_NO)\s*[:=]\s*([A-Za-z0-9_-]+)"),
            ("Location ID", r"\b(?:LocID|LocationID|Location\s*ID)\s*[:=]\s*([A-Za-z0-9_-]+)"),
            ("Carrier Index", r"\bCarrier\s+idx\s*[:=]\s*([A-Za-z0-9_-]+)"),
        ]
        for label, pattern in patterns:
            for match in re.finditer(pattern, message, flags=re.IGNORECASE):
                add(label, match.group(1))

        return candidates

    def _highlight_terms(self) -> list[str]:
        terms = [keyword for _mode, keyword in self.keywords if keyword.strip()]
        result_keyword = self.result_search_var.get().strip()
        if result_keyword:
            terms.append(result_keyword)
        return terms

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

    def clear_selected_keyword(self, _event=None) -> str:
        self.selected_keyword_index = None
        self.keyword_var.set("")
        self._render_keyword_tags()
        self.status_var.set("포함 키워드 선택을 취소했습니다.")
        return "break"

    def clear_selected_exclude_keyword(self, _event=None) -> str:
        self.selected_exclude_keyword_index = None
        self.exclude_keyword_var.set("")
        self._render_exclude_keyword_tags()
        self.status_var.set("제외 키워드 선택을 취소했습니다.")
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
            "always_include_bookmarks": self.always_include_bookmarks_var.get(),
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
        self.always_include_bookmarks_var.set(
            bool(preset.get("always_include_bookmarks", False))
        )
        self.preset_name_var.set(preset_name)
        self.keyword_var.set("")
        self.exclude_keyword_var.set("")
        self.selected_keyword_index = None
        self.selected_exclude_keyword_index = None
        self._refresh_keyword_listboxes()
        self._mark_keyword_filters_pending(f"검색 프리셋 불러옴: {preset_name}.")

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
                ("Log files", "*.log *.txt *.tslog"),
                ("All files", "*.*"),
            ),
        )
        if not paths:
            return
        self._add_paths(paths)

    @staticmethod
    def _analysis_file_rows(
        paths: list[str], file_types: dict[str, str]
    ) -> list[tuple[int, str, str, str]]:
        return [
            (
                index,
                file_types.get(Path(path).name, "UNKNOWN"),
                Path(path).name,
                path,
            )
            for index, path in enumerate(paths, start=1)
        ]

    def show_analysis_files(self) -> None:
        if not self.analyzed_paths:
            messagebox.showinfo(
                "분석 파일 목록",
                "아직 분석이 완료된 파일이 없습니다.",
            )
            return

        rows = self._analysis_file_rows(self.analyzed_paths, self.file_types)
        popup = Toplevel(self.root)
        popup.title(f"분석 파일 목록 ({len(rows)}개)")
        popup.geometry("1000x480")
        popup.minsize(720, 320)
        popup.transient(self.root)

        frame = ttk.Frame(popup, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=f"현재 분석 결과를 생성하는 데 사용된 파일 {len(rows)}개",
        ).pack(anchor="w", pady=(0, 8))

        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        tree = ttk.Treeview(
            table_frame,
            columns=("number", "type", "name", "path"),
            show="headings",
            selectmode="extended",
        )
        tree.heading("number", text="번호")
        tree.heading("type", text="로그 유형")
        tree.heading("name", text="파일명")
        tree.heading("path", text="전체 경로")
        tree.column("number", width=55, minwidth=45, anchor="center", stretch=False)
        tree.column("type", width=90, minwidth=75, anchor="center", stretch=False)
        tree.column("name", width=250, minwidth=140)
        tree.column("path", width=560, minwidth=260)
        for number, log_type, name, path in rows:
            tree.insert("", "end", iid=str(number), values=(number, log_type, name, path))

        vertical_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        horizontal_scroll = ttk.Scrollbar(
            table_frame, orient="horizontal", command=tree.xview
        )
        tree.configure(
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set,
        )
        tree.grid(row=0, column=0, sticky="nsew")
        vertical_scroll.grid(row=0, column=1, sticky="ns")
        horizontal_scroll.grid(row=1, column=0, sticky="ew")

        def copy_paths(selected_only: bool) -> None:
            selected = tree.selection() if selected_only else tree.get_children()
            if not selected:
                messagebox.showinfo("경로 복사", "복사할 파일을 선택하세요.")
                return
            paths_to_copy = [str(tree.item(item, "values")[3]) for item in selected]
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(paths_to_copy))
            self.status_var.set(f"분석 파일 경로 {len(paths_to_copy)}개를 복사했습니다.")

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=(10, 0))
        ttk.Button(
            button_frame,
            text="선택 경로 복사",
            command=lambda: copy_paths(True),
        ).pack(side="left")
        ttk.Button(
            button_frame,
            text="전체 경로 복사",
            command=lambda: copy_paths(False),
        ).pack(side="left", padx=(6, 0))
        ttk.Button(button_frame, text="닫기", command=popup.destroy).pack(side="right")

        popup.bind("<Escape>", lambda _event: popup.destroy())
        popup.after_idle(tree.focus_set)

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
            if not is_supported_log_path(p):
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
            self.status_var.set(
                "추가된 로그 파일이 없습니다. .log, .txt 또는 .tslog 파일을 선택하세요."
            )
        self.summary_var.set(", ".join(Path(path).name for path in self.paths[:4]))

    def clear_result_search(self) -> None:
        if not self.result_search_var.get().strip():
            return
        self.result_search_var.set("")
        if self._first_selected_display_index() is not None:
            self.show_selected_detail()
        self.status_var.set("결과 내 찾기 검색어를 지웠습니다.")

    @staticmethod
    def _find_navigation_index(
        current_index: int | None, matching_indices: list[int], direction: int
    ) -> int | None:
        if not matching_indices:
            return None
        if current_index is None:
            return matching_indices[-1] if direction < 0 else matching_indices[0]
        if direction < 0:
            return next(
                (index for index in reversed(matching_indices) if index < current_index),
                matching_indices[-1],
            )
        return next(
            (index for index in matching_indices if index > current_index),
            matching_indices[0],
        )

    def _result_match_indices(self, keyword: str) -> list[int]:
        matches = search_multiple_keywords(
            self.filtered_entries,
            [keyword],
            match_all=True,
            case_sensitive=self.case_sensitive_var.get(),
            use_regex=self.regex_search_var.get(),
        )
        matched_entry_ids = {id(match.entry) for match in matches}
        return [
            index
            for index, entry in enumerate(self.filtered_entries)
            if id(entry) in matched_entry_ids
        ]

    def find_result_match(self, direction: int, _event=None) -> str:
        keyword = self.result_search_var.get().strip()
        if not keyword:
            self.status_var.set("결과 내 검색어를 입력하세요.")
            return "break"
        self._navigate_result_match(direction)
        return "break"

    def _navigate_result_match(self, direction: int) -> bool:
        keyword = self.result_search_var.get().strip()
        matching_indices = self._result_match_indices(keyword)
        current_index = self._first_selected_display_index()
        target_index = self._find_navigation_index(
            current_index, matching_indices, direction
        )
        if target_index is None:
            self.status_var.set(f"찾기 결과가 없습니다. ({keyword})")
            return False
        item = str(target_index)
        if not self.tree.exists(item):
            self.refresh_table(
                keep_detail=True,
                row_limit_override=target_index + 1,
            )
        if not self.tree.exists(item):
            self.status_var.set("찾기 결과를 표시할 수 없습니다.")
            return False
        self.tree.selection_set(item)
        self.tree.focus(item)
        self.tree.see(item)
        self.show_selected_detail()
        if self.search_view_mode_active:
            self.on_filtered_result_selected_in_search_mode()
        self._focus_result_table()
        direction_label = "이전" if direction < 0 else "다음"
        match_position = matching_indices.index(target_index) + 1
        self.status_var.set(
            f"{direction_label} 찾기: 일치 {match_position:,}/{len(matching_indices):,}, "
            f"결과 행 {target_index + 1:,}/{len(self.filtered_entries):,} ({keyword})"
        )
        return True

    def add_keyword(self) -> None:
        keyword = self.keyword_var.get().strip()
        if not keyword:
            return
        mode = self.keyword_mode_var.get().strip().upper()
        if mode not in {"AND", "OR"}:
            mode = "AND"
        changed = False
        if self.selected_keyword_index is not None:
            index = self.selected_keyword_index
            changed = self.keywords[index] != (mode, keyword)
            self.keywords[index] = (mode, keyword)
            self.selected_keyword_index = None
        elif (mode, keyword) not in self.keywords:
            self.keywords.append((mode, keyword))
            changed = True
        self.keyword_var.set("")
        self._render_keyword_tags()
        if changed:
            self._mark_keyword_filters_pending()

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
        self._mark_keyword_filters_pending()
        return "break"

    def clear_keywords(self) -> None:
        if not self.keywords:
            return
        self.keywords.clear()
        self.selected_keyword_index = None
        self.keyword_var.set("")
        self._render_keyword_tags()
        self._mark_keyword_filters_pending()

    def _keyword_label(self, mode: str, keyword: str) -> str:
        return f"[{mode}] {keyword}"

    def add_exclude_keyword(self) -> None:
        keyword = self.exclude_keyword_var.get().strip()
        if not keyword:
            return
        changed = False
        if self.selected_exclude_keyword_index is not None:
            index = self.selected_exclude_keyword_index
            changed = self.exclude_keywords[index] != keyword
            self.exclude_keywords[index] = keyword
            self.selected_exclude_keyword_index = None
        elif keyword not in self.exclude_keywords:
            self.exclude_keywords.append(keyword)
            changed = True
        self.exclude_keyword_var.set("")
        self._render_exclude_keyword_tags()
        if changed:
            self._mark_keyword_filters_pending()

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
        self._mark_keyword_filters_pending()
        return "break"

    def clear_exclude_keywords(self) -> None:
        if not self.exclude_keywords:
            return
        self.exclude_keywords.clear()
        self.selected_exclude_keyword_index = None
        self.exclude_keyword_var.set("")
        self._render_exclude_keyword_tags()
        self._mark_keyword_filters_pending()

    def _mark_keyword_filters_pending(self, prefix: str = "키워드 변경됨.") -> None:
        self.status_var.set(f"{prefix} 검색/필터 적용 버튼 또는 F5를 눌러 반영하세요.")

    def analyze(self) -> None:
        if not self.paths:
            messagebox.showinfo("파일 선택", "먼저 로그 파일을 선택하세요.")
            return
        try:
            excluded_ranges = self._excluded_ceid_ranges()
        except ValueError as exc:
            messagebox.showerror("CEID 제외 범위 오류", str(exc))
            return
        self._disable_bookmark_only_for_analysis()
        self.save_s6f11_exclude_settings()
        self.save_db_settings()
        worker_count = self._parse_worker_count(len(self.paths))
        db_enabled = self.db_annotation_var.get()
        db_server = self.db_server_var.get().strip() or DEFAULT_SERVER
        db_database = self.db_database_var.get().strip() or DEFAULT_DATABASE
        db_driver = self.db_driver_var.get().strip() or DEFAULT_DRIVER
        skip_setup_dump = self.skip_setup_var.get()
        analysis_paths = list(self.paths)
        self.status_var.set(
            f"로그 로딩 준비 중... 파일 {len(analysis_paths)}개를 {worker_count}개 스레드로 파싱합니다."
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
                analysis_paths,
            ),
            daemon=True,
        )
        worker.start()

    @staticmethod
    def _parse_worker_count(file_count: int) -> int:
        cpu_count = os.cpu_count() or 1
        return max(1, min(file_count, cpu_count, 8))

    def _count_total_lines(self, paths: list[str]) -> int:
        total = 0
        for path in paths:
            total += self._count_file_lines(path)
        return total

    @staticmethod
    def _count_file_lines(path: str) -> int:
        line_count = 0
        last_byte = b""
        with open(path, "rb") as handle:
            while chunk := handle.read(1024 * 1024):
                line_count += chunk.count(b"\n")
                last_byte = chunk[-1:]
        if last_byte and last_byte != b"\n":
            line_count += 1
        return line_count

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
        analysis_paths: list[str],
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
            total_lines = self._count_total_lines(analysis_paths)
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
                analysis_paths,
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
                    analysis_paths,
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
        analysis_paths: list[str],
    ) -> None:
        self.entries = entries
        self.analyzed_paths = analysis_paths
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
        self.analyzed_paths.clear()
        self.entries = []
        self.filtered_entries = []
        self.search_matches = []
        self.matched_keywords_by_entry = {}
        self.time_filter_start = None
        self.time_filter_end = None
        self._update_time_filter_summary()
        self.skipped_setup_lines = 0
        self.file_types = {}
        self.gem300_events = []
        self.alarms = []
        self.carrier_roundtrip_rows: list[CarrierRoundtripRow] = []
        self.roundtrip_row_refs: dict[str, CarrierRoundtripRow] = {}
        self.report_variables = {}
        self.sxfy_types = []
        self.sxfy_filter_vars = {}
        self._build_sxfy_menu()
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        if hasattr(self, "roundtrip_tree"):
            for item in self.roundtrip_tree.get_children():
                self.roundtrip_tree.delete(item)
        self._clear_detail()
        self.summary_var.set("")
        self.progress.configure(value=0)
        self.progress_percent_var.set("")
        self.status_var.set("분석 내용이 초기화되었습니다. 로그 파일을 다시 선택하세요.")

    def save_session(self) -> None:
        path = filedialog.asksaveasfilename(
            title="세션 저장",
            defaultextension=".json",
            filetypes=(("GEM300 session", "*.json"), ("All files", "*.*")),
        )
        if not path:
            return
        data = self._build_session_data()
        Path(path).write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.status_var.set(f"세션 저장 완료: {path}")
    def load_session(self) -> None:
        path = filedialog.askopenfilename(
            title="세션 불러오기",
            filetypes=(("GEM300 session", "*.json"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("세션 파일 형식이 올바르지 않습니다.")
            missing_paths = self._apply_session_data(data)
        except Exception as exc:
            messagebox.showerror("세션 불러오기", str(exc))
            return
        self._save_settings()
        self.status_var.set(f"세션 불러오기 완료: {path}")
        if missing_paths:
            messagebox.showwarning(
                "세션 불러오기",
                "존재하지 않는 파일은 제외했습니다.\n\n" + "\n".join(missing_paths[:10]),
            )
        if self.paths and messagebox.askyesno("세션 불러오기", "복원된 파일을 바로 분석할까요?"):
            self.analyze()

    def _build_session_data(self) -> dict:
        return {
            "version": 1,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "paths": list(self.paths),
            "keywords": [
                {"mode": mode, "keyword": keyword} for mode, keyword in self.keywords
            ],
            "exclude_keywords": list(self.exclude_keywords),
            "filters": {
                "case_sensitive": self.case_sensitive_var.get(),
                "regex_search": self.regex_search_var.get(),
                "mmi": self.filter_mmi_var.get(),
                "secs": self.filter_secs_var.get(),
                "bookmark_only": self.bookmark_only_var.get(),
                "always_include_bookmarks": self.always_include_bookmarks_var.get(),
                "sxfy_selected": self._selected_sxfy_filters_for_save(),
                "skip_setup_dump": self.skip_setup_var.get(),
                "time_filter": {
                    "start": self.time_filter_start.isoformat()
                    if self.time_filter_start
                    else None,
                    "end": self.time_filter_end.isoformat()
                    if self.time_filter_end
                    else None,
                },
            },
            "view": {
                "visible_columns": list(self.visible_columns),
                "column_order": self._column_order_for_save(),
                "column_visibility": {
                    column: self.column_visible_vars[column].get() for column in COLUMNS
                },
                "display_rows": self.display_rows_var.get(),
                "context_rows": self.context_rows_var.get(),
                "detail_header_enabled": self.detail_header_var.get(),
                "compare_mode_enabled": self.compare_mode_var.get(),
                "flow_highlight_enabled": self.flow_highlight_var.get(),
                "bookmark_timeline_visible": self.bookmark_timeline_visible_var.get(),
                "stats_panel_visible": self.stats_panel_visible_var.get(),
                "theme": self.theme_var.get(),
            },
            "db": {
                "annotation_enabled": self.db_annotation_var.get(),
                "server": self.db_server_var.get(),
                "database": self.db_database_var.get(),
                "driver": self.db_driver_var.get(),
            },
            "exclude_s6f11": {
                "enabled": self.exclude_s6f11_var.get(),
                "items": self.exclude_ceid_items,
            },
            "bookmarks": self.bookmarks,
        }

    def _apply_session_data(self, data: dict) -> list[str]:
        raw_paths = [str(path) for path in data.get("paths", []) if str(path).strip()]
        existing_paths = [path for path in raw_paths if Path(path).exists()]
        missing_paths = [path for path in raw_paths if not Path(path).exists()]
        self.paths = existing_paths

        self.keywords = []
        for item in data.get("keywords", []):
            if not isinstance(item, dict):
                continue
            mode = str(item.get("mode", "AND")).upper()
            keyword = str(item.get("keyword", "")).strip()
            if mode in {"AND", "OR"} and keyword:
                self.keywords.append((mode, keyword))
        self.exclude_keywords = [
            str(keyword).strip()
            for keyword in data.get("exclude_keywords", [])
            if str(keyword).strip()
        ]
        self.selected_keyword_index = None
        self.selected_exclude_keyword_index = None
        self.keyword_var.set("")
        self.exclude_keyword_var.set("")
        self._render_keyword_tags()
        self._render_exclude_keyword_tags()

        filters = data.get("filters", {})
        if isinstance(filters, dict):
            self.case_sensitive_var.set(bool(filters.get("case_sensitive", False)))
            self.regex_search_var.set(bool(filters.get("regex_search", False)))
            self.filter_mmi_var.set(bool(filters.get("mmi", True)))
            self.filter_secs_var.set(bool(filters.get("secs", True)))
            self.bookmark_only_var.set(bool(filters.get("bookmark_only", False)))
            self.always_include_bookmarks_var.set(
                bool(filters.get("always_include_bookmarks", False))
            )
            self.skip_setup_var.set(bool(filters.get("skip_setup_dump", True)))
            time_filter = filters.get("time_filter", {})
            if isinstance(time_filter, dict):
                self.time_filter_start = self._parse_session_datetime(
                    time_filter.get("start")
                )
                self.time_filter_end = self._parse_session_datetime(time_filter.get("end"))
                self._update_time_filter_summary()
            sxfy_selected = filters.get("sxfy_selected")
            if isinstance(sxfy_selected, list):
                selected = {str(message_type).upper() for message_type in sxfy_selected}
                self.settings["sxfy_selected_filters"] = list(selected)
                for message_type, variable in self.sxfy_filter_vars.items():
                    variable.set(message_type in selected)

        view = data.get("view", {})
        if isinstance(view, dict):
            self._restore_session_columns(view)
            self.display_rows_var.set(int(view.get("display_rows", self.display_rows_var.get())))
            self.context_rows_var.set(int(view.get("context_rows", self.context_rows_var.get())))
            self.detail_header_var.set(bool(view.get("detail_header_enabled", True)))
            self.compare_mode_var.set(bool(view.get("compare_mode_enabled", False)))
            self.flow_highlight_var.set(bool(view.get("flow_highlight_enabled", True)))
            self.bookmark_timeline_visible_var.set(bool(view.get("bookmark_timeline_visible", True)))
            self.stats_panel_visible_var.set(bool(view.get("stats_panel_visible", True)))
            theme = str(view.get("theme", self.theme_var.get())).lower()
            if theme in THEMES:
                self.theme_var.set(theme)
            self._apply_bookmark_timeline_visibility(save=False)
            self._apply_stats_panel_visibility(save=False)

        db = data.get("db", {})
        if isinstance(db, dict):
            self.db_annotation_var.set(bool(db.get("annotation_enabled", True)))
            self.db_server_var.set(str(db.get("server", DEFAULT_SERVER)))
            self.db_database_var.set(str(db.get("database", DEFAULT_DATABASE)))
            self.db_driver_var.set(str(db.get("driver", DEFAULT_DRIVER)))
            if self.db_database_var.get() not in self.db_database_values:
                self.db_database_values.insert(0, self.db_database_var.get())
            if hasattr(self, "db_database_combo"):
                self.db_database_combo.configure(values=self.db_database_values)

        exclude_s6f11 = data.get("exclude_s6f11", {})
        if isinstance(exclude_s6f11, dict):
            self.exclude_s6f11_var.set(bool(exclude_s6f11.get("enabled", True)))
            items = exclude_s6f11.get("items", [])
            if isinstance(items, list):
                self.exclude_ceid_items = items
                self.exclude_ceid_summary_var.set(self._exclude_ceid_summary())

        bookmarks = data.get("bookmarks", {})
        if isinstance(bookmarks, dict):
            self.bookmarks = {str(key): str(value) for key, value in bookmarks.items()}

        self.entries = []
        self.filtered_entries = []
        self.search_matches = []
        self.matched_keywords_by_entry = {}
        self._build_sxfy_menu()
        self.refresh_table()
        self.summary_var.set(", ".join(Path(path).name for path in self.paths[:4]))
        return missing_paths

    @staticmethod
    def _parse_session_datetime(value) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None

    def _restore_session_columns(self, view: dict) -> None:
        order = [
            str(column)
            for column in view.get("column_order", [])
            if str(column) in COLUMNS
        ]
        visible = [
            str(column)
            for column in view.get("visible_columns", [])
            if str(column) in COLUMNS
        ]
        visibility = view.get("column_visibility", {})
        if not visible and isinstance(visibility, dict):
            visible = [
                column
                for column in (order or list(COLUMNS))
                if bool(visibility.get(column, True))
            ]
        if not visible:
            visible = list(COLUMNS)
        ordered_visible = [column for column in order if column in visible]
        ordered_visible.extend(column for column in visible if column not in ordered_visible)
        self.visible_columns = ordered_visible or ["message"]
        for column in COLUMNS:
            self.column_visible_vars[column].set(column in self.visible_columns)
        self._apply_visible_columns(save=False)

    def apply_filters(self) -> None:
        self._filter_generation += 1
        generation = self._filter_generation
        entries = list(self.entries)
        keywords = list(self.keywords)
        exclude_keywords = list(self.exclude_keywords)
        selected_types: set[str] = set()
        if self.filter_mmi_var.get():
            selected_types.add("MMI")
        if self.filter_secs_var.get():
            selected_types.add("SECS")
        sxfy_filter = self._active_sxfy_filter_set()
        time_filter_start = self.time_filter_start
        time_filter_end = self.time_filter_end
        bookmark_only = self.bookmark_only_var.get()
        bookmarked_keys = set(self.bookmarks)
        case_sensitive = self.case_sensitive_var.get()
        use_regex = self.regex_search_var.get()
        always_include_bookmarks = self.always_include_bookmarks_var.get()

        self.status_var.set("필터링 중...")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.progress_percent_var.set("")
        self._set_controls_busy(True)

        thread = threading.Thread(
            target=self._filter_worker,
            args=(
                generation,
                entries,
                keywords,
                exclude_keywords,
                selected_types,
                sxfy_filter,
                time_filter_start,
                time_filter_end,
                bookmark_only,
                bookmarked_keys,
                case_sensitive,
                use_regex,
                always_include_bookmarks,
            ),
            daemon=True,
        )
        thread.start()

    def _filter_worker(
        self,
        generation: int,
        entries: list[LogEntry],
        keywords: list[tuple[str, str]],
        exclude_keywords: list[str],
        selected_types: set[str],
        sxfy_filter: set[str] | None,
        time_filter_start: datetime | None,
        time_filter_end: datetime | None,
        bookmark_only: bool,
        bookmarked_keys: set[str],
        case_sensitive: bool,
        use_regex: bool,
        always_include_bookmarks: bool,
    ) -> None:
        try:
            filtered_entries, search_matches, matched_keywords_by_entry = (
                self._build_filtered_entries(
                    entries,
                    keywords,
                    exclude_keywords,
                    selected_types,
                    sxfy_filter,
                    time_filter_start,
                    time_filter_end,
                    bookmark_only,
                    bookmarked_keys,
                    case_sensitive,
                    use_regex,
                    always_include_bookmarks,
                )
            )
        except Exception as exc:
            error = str(exc)
            self.root.after(0, lambda: self._filter_failed(generation, error))
            return
        self.root.after(
            0,
            lambda: self._filter_complete(
                generation,
                filtered_entries,
                search_matches,
                matched_keywords_by_entry,
            ),
        )

    def _build_filtered_entries(
        self,
        entries: list[LogEntry],
        keywords: list[tuple[str, str]],
        exclude_keywords: list[str],
        selected_types: set[str],
        sxfy_filter: set[str] | None,
        time_filter_start: datetime | None,
        time_filter_end: datetime | None,
        bookmark_only: bool,
        bookmarked_keys: set[str],
        case_sensitive: bool,
        use_regex: bool,
        always_include_bookmarks: bool = False,
    ) -> tuple[list[LogEntry], list[SearchMatch], dict[int, str]]:
        def is_bookmarked(entry: LogEntry) -> bool:
            return self._entry_key(entry) in bookmarked_keys

        base_entries = [
            entry for entry in entries if entry.log_type.value in selected_types
        ]
        if sxfy_filter is not None:
            base_entries = [
                entry
                for entry in base_entries
                if entry.log_type.value != "SECS"
                or self._entry_sxfy_type(entry) in sxfy_filter
            ]
        if time_filter_start is not None:
            base_entries = [
                entry for entry in base_entries if entry.timestamp >= time_filter_start
            ]
        if time_filter_end is not None:
            base_entries = [
                entry for entry in base_entries if entry.timestamp <= time_filter_end
            ]
        matched_keywords_by_entry: dict[int, str] = {}
        if keywords or exclude_keywords:
            and_keywords = [
                keyword for mode, keyword in keywords if mode == "AND"
            ]
            or_keywords = [
                keyword for mode, keyword in keywords if mode == "OR"
            ]
            search_matches = search_multiple_keywords(
                base_entries,
                and_keywords,
                or_keywords=or_keywords,
                exclude_keywords=exclude_keywords,
                match_all=True,
                case_sensitive=case_sensitive,
                use_regex=use_regex,
                log_types=selected_types,
            )
            filtered_entries = [match.entry for match in search_matches]
            matched_keywords_by_entry = {
                id(match.entry): match.keyword for match in search_matches
            }
            if always_include_bookmarks:
                filtered_ids = {id(entry) for entry in filtered_entries}
                filtered_entries = [
                    entry
                    for entry in base_entries
                    if id(entry) in filtered_ids or is_bookmarked(entry)
                ]
        else:
            search_matches = []
            filtered_entries = base_entries
        if bookmark_only:
            filtered_entries = [
                entry for entry in filtered_entries if is_bookmarked(entry)
            ]
            if search_matches:
                filtered_ids = {id(entry) for entry in filtered_entries}
                search_matches = [
                    match for match in search_matches if id(match.entry) in filtered_ids
                ]
                matched_keywords_by_entry = {
                    id(match.entry): match.keyword for match in search_matches
                }
        return filtered_entries, search_matches, matched_keywords_by_entry

    def _filter_complete(
        self,
        generation: int,
        filtered_entries: list[LogEntry],
        search_matches: list[SearchMatch],
        matched_keywords_by_entry: dict[int, str],
    ) -> None:
        if generation != self._filter_generation:
            return
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.progress_percent_var.set("")
        self._set_controls_busy(False)
        self.filtered_entries = filtered_entries
        self.search_matches = search_matches
        self.matched_keywords_by_entry = matched_keywords_by_entry
        focus_entry_key = self._pending_filter_restore_key
        self._pending_filter_restore_key = None
        self.refresh_table(focus_entry_key=focus_entry_key)
        if focus_entry_key and self._filtered_index_for_entry_key(focus_entry_key) is not None:
            self.status_var.set("필터링 완료. 선택 로그 위치로 이동했습니다.")
        else:
            self.status_var.set("필터링 완료")

    def _filter_failed(self, generation: int, error: str) -> None:
        if generation != self._filter_generation:
            return
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.progress_percent_var.set("")
        self._set_controls_busy(False)
        self.status_var.set(f"필터링 실패: {error}")
        messagebox.showerror("필터링 실패", error)

    def refresh_table(
        self,
        keep_detail: bool = False,
        focus_entry_key: str | None = None,
        row_limit_override: int | None = None,
    ) -> None:
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        display_limit = max(1, self.display_rows_var.get())
        if row_limit_override is not None:
            display_limit = max(display_limit, row_limit_override)
        if focus_entry_key:
            focus_index = self._filtered_index_for_entry_key(focus_entry_key)
            if focus_index is not None:
                display_limit = max(display_limit, focus_index + 1)
        rows = self.filtered_entries[:display_limit]
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
                    self._time_delta_for_index(index),
                ),
                tags=("bookmarked",) if bookmarked else (),
            )
        hidden = max(0, len(self.filtered_entries) - len(rows))
        if hasattr(self, "filtered_result_title_var"):
            self.filtered_result_title_var.set(
                f"필터 결과 ({len(self.filtered_entries):,}건, 표시 {len(rows):,}건"
                + (f", {hidden:,}건 더 있음)" if hidden else ")")
            )
        self.summary_var.set(
            f"표시 {len(rows)}건 / 필터 결과 {len(self.filtered_entries)}건"
            + (f" ({hidden}건 더 있음)" if hidden else "")
        )
        self._refresh_bookmark_timeline()
        self._refresh_stats_panel()
        if getattr(self, "search_view_mode_active", False):
            self.refresh_all_logs_table()
        if focus_entry_key and self._select_filtered_entry_by_key(focus_entry_key):
            return
        if not keep_detail:
            self._clear_detail()

    def show_selected_detail(self, _event=None) -> None:
        self._detail_source = "filtered"
        selected_indices = self._selected_display_indices()
        if not selected_indices:
            self._clear_detail()
            self._sync_bookmark_timeline_selection()
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
            pane = self._create_detail_pane(entry, index, self.filtered_entries)
            self.detail_pane.add(pane, weight=1)
        self._sync_bookmark_timeline_selection()

    def show_selected_full_log_detail(self, _event=None) -> None:
        if not self.search_view_mode_active:
            return
        selected_indices = self._selected_full_log_indices()
        if not selected_indices:
            return
        self._detail_source = "all"
        self._render_selected_entry_details(self.entries, selected_indices)

    def _selected_full_log_indices(self) -> list[int]:
        return sorted(
            int(item)
            for item in self.all_logs_tree.selection()
            if item.isdigit() and 0 <= int(item) < len(self.entries)
        )

    def _render_selected_entry_details(
        self, source_entries: list[LogEntry], selected_indices: list[int]
    ) -> None:
        self._clear_detail()
        orient = "vertical" if self.detail_horizontal_var.get() else "horizontal"
        self.detail_pane = ttk.PanedWindow(self.detail_pane_container, orient=orient)
        self.detail_pane.grid(row=0, column=0, sticky="nsew")
        for index in selected_indices[:8]:
            entry = source_entries[index]
            pane = self._create_detail_pane(entry, index, source_entries)
            self.detail_pane.add(pane, weight=1)

    def refresh_selected_detail(self) -> None:
        if self._detail_source == "all" and self.search_view_mode_active:
            self.show_selected_full_log_detail()
            return
        self.show_selected_detail()

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
        return aligned_line_diff(left_lines, right_lines)

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

    def _create_detail_pane(
        self,
        entry: LogEntry,
        index: int,
        source_entries: list[LogEntry] | None = None,
    ) -> ttk.Frame:
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
        detail_text.tag_configure(
            "flow_match",
            background=colors["flow_highlight_bg"],
            foreground=colors["flow_highlight_fg"],
        )
        detail_text.tag_configure("selected_log", background=colors["select_bg"])
        detail = self._format_detail_with_context(index, source_entries)
        detail_text.insert("1.0", detail)
        self._highlight_flow_terms(detail_text, entry)
        self._highlight_detail_text(detail_text)
        detail_text.tag_raise("match")
        return pane

    def _format_detail_with_context(
        self,
        selected_index: int,
        source_entries: list[LogEntry] | None = None,
    ) -> str:
        entries = self.filtered_entries if source_entries is None else source_entries
        context = max(0, self.context_rows_var.get())
        start = max(0, selected_index - context)
        end = min(len(entries), selected_index + context + 1)
        blocks: list[str] = []
        for index in range(start, end):
            if self.detail_header_var.get():
                prefix = ">>> 선택 로그" if index == selected_index else "    주변 로그"
                blocks.append(prefix)
            blocks.append(self._format_single_detail(entries[index], index, entries))
        return "\n\n".join(blocks)

    def _format_single_detail(
        self,
        entry: LogEntry,
        index: int,
        source_entries: list[LogEntry] | None = None,
    ) -> str:
        message = entry.message
        message = _format_xml_in_message(message)
        if not self.detail_header_var.get():
            return message

        rows = self._visible_detail_header_rows(entry, index, source_entries)
        if not rows:
            return message
        header = "\n".join(f"{field}: {value}" for field, value in rows)
        return f"{header}\n\n{message}"

    def _visible_detail_header_rows(
        self,
        entry: LogEntry,
        index: int,
        source_entries: list[LogEntry] | None = None,
    ) -> list[tuple[str, str]]:
        entries = self.filtered_entries if source_entries is None else source_entries
        time_delta = ""
        if 0 < index < len(entries):
            time_delta = self._format_time_delta(
                entries[index].timestamp - entries[index - 1].timestamp
            )
        values = dict(
            zip(
                COLUMNS,
                _entry_to_values(
                    entry,
                    self.matched_keywords_by_entry.get(id(entry), ""),
                    self._is_bookmarked(entry),
                    self._entry_memo(entry),
                    time_delta,
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

    def _highlight_flow_terms(self, detail_text: Text, selected_entry: LogEntry) -> None:
        if not self.flow_highlight_var.get():
            return
        terms = self._flow_highlight_terms(selected_entry)
        if not terms:
            return
        flags = 0 if self.case_sensitive_var.get() else re.IGNORECASE
        content = detail_text.get("1.0", "end-1c")
        for term in terms:
            pattern = re.compile(re.escape(term), flags)
            for match in pattern.finditer(content):
                if match.start() == match.end():
                    continue
                start = f"1.0+{match.start()}c"
                end = f"1.0+{match.end()}c"
                detail_text.tag_add("flow_match", start, end)

    def _flow_highlight_terms(self, entry: LogEntry) -> list[str]:
        flow_labels = {
            "Carrier ID",
            "Substrate ID",
            "Acquired ID",
            "Location ID",
            "CEID",
            "이벤트명",
        }
        terms: list[str] = []
        for label, keyword in self._related_search_candidates(entry):
            if label not in flow_labels:
                continue
            cleaned = keyword.strip()
            if len(cleaned) < 3:
                continue
            if cleaned not in terms:
                terms.append(cleaned)
        return sorted(terms, key=len, reverse=True)

    def refresh_carrier_roundtrip(self) -> None:
        carrier_id = self.carrier_roundtrip_var.get().strip()
        for item in self.roundtrip_tree.get_children():
            self.roundtrip_tree.delete(item)
        self.roundtrip_row_refs = {}
        self.carrier_roundtrip_rows = []
        if not carrier_id:
            self.status_var.set("Carrier ID를 입력하세요.")
            return
        if not self.entries:
            self.status_var.set("먼저 로그를 분석하세요.")
            return
        rows = build_carrier_roundtrip(
            carrier_id,
            self.entries,
            self.gem300_events,
            self.alarms,
        )
        self.carrier_roundtrip_rows = rows
        for index, row in enumerate(rows):
            item_id = str(index)
            self.roundtrip_row_refs[item_id] = row
            self.roundtrip_tree.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    row.display_time,
                    self._format_roundtrip_gap(row.gap_ms),
                    row.port_no or "",
                    row.level,
                    row.state,
                    row.detail.replace("\n", " ")[:1000],
                    row.source,
                    str(row.line_no),
                ),
                tags=(row.level,) if row.level in {"WARN", "ERROR"} else (),
            )
        if rows:
            self.status_var.set(f"Carrier roundtrip 조회 완료: {carrier_id} ({len(rows)}건)")
        else:
            self.status_var.set(f"Carrier roundtrip 결과 없음: {carrier_id}")

    def on_roundtrip_row_select(self, _event=None) -> None:
        selected = self.roundtrip_tree.selection()
        if not selected:
            return
        row = self.roundtrip_row_refs.get(selected[0])
        if row is None or row.entry is None:
            return
        self._select_log_entry(row.entry)

    def _select_log_entry(self, entry: LogEntry) -> None:
        target_key = self._entry_key(entry)
        for index, candidate in enumerate(self.filtered_entries):
            if self._entry_key(candidate) != target_key:
                continue
            if index >= max(1, self.display_rows_var.get()):
                self.display_rows_var.set(index + 1)
                self.refresh_table(keep_detail=True)
            item_id = str(index)
            if item_id in self.tree.get_children():
                self.tree.selection_set(item_id)
                self.tree.focus(item_id)
                self.tree.see(item_id)
                self.show_selected_detail()
                self.status_var.set(f"원본 로그로 이동: {entry.source_file}:{entry.line_no}")
                return
        self.status_var.set(
            "선택한 roundtrip row의 원본 로그가 현재 필터 결과에 없습니다. 필터를 해제한 뒤 다시 선택하세요."
        )

    def _format_roundtrip_gap(self, gap_ms: int | None) -> str:
        if gap_ms is None:
            return "-"
        return self._format_time_delta(timedelta(milliseconds=gap_ms))
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
            for index, entry in enumerate(self.filtered_entries):
                writer.writerow(
                    _entry_to_values(
                        entry,
                        self.matched_keywords_by_entry.get(id(entry), ""),
                        self._is_bookmarked(entry),
                        self._entry_memo(entry),
                        self._time_delta_for_index(index),
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
        report_entries = self.filtered_entries
        report = generate_report(
            report_entries,
            self.gem300_events,
            self.alarms,
            self.search_matches,
            keyword=self._filter_description(),
            skipped_setup_lines=self.skipped_setup_lines,
            file_summary=self.file_types,
            format=report_format,
        )
        Path(path).write_text(report, encoding="utf-8")
        self.status_var.set(f"Report saved ({len(report_entries):,} rows): {path}")
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
        if self.always_include_bookmarks_var.get():
            parts.append("북마크 키워드 조건 예외")
        if self.time_filter_start is not None or self.time_filter_end is not None:
            parts.append("시간: " + self.time_filter_summary_var.get())
        return " / ".join(parts)

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    startup_smoke_marker = os.environ.get(STARTUP_SMOKE_MARKER_ENV)
    try:
        app = Gem300DesktopApp()
        if startup_smoke_marker:
            app.root.update_idletasks()
            Path(startup_smoke_marker).write_text(
                f"GEM300 Log Analyzer v{__version__} startup OK",
                encoding="utf-8",
            )
            app.root.destroy()
            return
        app.run()
    except BaseException:
        if startup_smoke_marker:
            try:
                Path(f"{startup_smoke_marker}.error").write_text(
                    traceback.format_exc(),
                    encoding="utf-8",
                )
            except OSError:
                pass
        raise


if __name__ == "__main__":
    main()

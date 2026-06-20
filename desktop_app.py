"""Tkinter desktop UI for GEM300 Log Analyzer."""

from __future__ import annotations

import csv
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
    filedialog,
    messagebox,
)
from tkinter import ttk
from xml.dom import minidom

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
APP_ICON_PNG = ROOT / "assets" / "app_icon.png"
APP_ICON_ICO = ROOT / "assets" / "app_icon.ico"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gem300_log_analyzer.analysis.alarm_summary import extract_alarms, summarize_alarms
from gem300_log_analyzer.analysis.gem300_trace import extract_gem300_events
from gem300_log_analyzer.analysis.keyword_search import search_multiple_keywords
from gem300_log_analyzer.analysis.s6f11_variables import (
    annotate_s6f11_variables,
    extract_s6f11_rptids,
)
from gem300_log_analyzer.db.event_lookup import load_event_names
from gem300_log_analyzer.db.report_variable_lookup import ReportVariable, load_report_variables
from gem300_log_analyzer.export.report_export import generate_report
from gem300_log_analyzer.models import LogEntry, SearchMatch
from gem300_log_analyzer.parsers.log_loader import parse_paths

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None


COLUMNS = (
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
APP_CONFIG_DIR = Path(
    os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
) / "GEM300LogAnalyzer"
APP_CONFIG_PATH = APP_CONFIG_DIR / "desktop_settings.json"

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


def _entry_to_values(entry: LogEntry, matched_keywords: str = "") -> tuple[str, ...]:
    level_channel = entry.level_name or (
        f"CH {entry.channel}" if entry.channel is not None else ""
    )
    return (
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
        self.root = TkinterDnD.Tk() if TkinterDnD is not None else Tk()
        self.root.title("GEM300 Log Analyzer")
        self._set_window_icon()
        self.root.geometry("1400x820")
        self.root.minsize(1050, 640)

        self.paths: list[str] = []
        self.entries: list[LogEntry] = []
        self.filtered_entries: list[LogEntry] = []
        self.search_matches: list[SearchMatch] = []
        self.skipped_setup_lines = 0
        self.file_types: dict[str, str] = {}
        self.gem300_events = []
        self.alarms = []
        self.report_variables: dict[int, list[ReportVariable]] = {}
        self.settings = self._load_settings()

        self.keyword_var = StringVar()
        self.keyword_mode_var = StringVar(value="AND")
        self.exclude_keyword_var = StringVar()
        self.keywords: list[tuple[str, str]] = []
        self.exclude_keywords: list[str] = []
        self.matched_keywords_by_entry: dict[int, str] = {}
        self.case_sensitive_var = BooleanVar(value=False)
        self.regex_search_var = BooleanVar(value=False)
        self.filter_mmi_var = BooleanVar(value=True)
        self.filter_secs_var = BooleanVar(value=True)
        self.skip_setup_var = BooleanVar(value=True)
        self.exclude_s6f11_var = BooleanVar(
            value=bool(self.settings.get("exclude_s6f11_enabled", True))
        )
        self.exclude_ceid_var = StringVar(
            value=str(self.settings.get("exclude_s6f11_ceid_ranges", "411001-411604"))
        )
        self.detail_vertical_var = BooleanVar(value=True)
        self.detail_wrap_var = BooleanVar(value=True)
        self.display_rows_var = IntVar(value=5000)
        self.status_var = StringVar(value="로그 파일을 선택하세요.")
        self.summary_var = StringVar(value="")
        visible_columns = self.settings.get("visible_columns")
        if not isinstance(visible_columns, list):
            visible_columns = list(COLUMNS)
        self.visible_columns: list[str] = [
            column for column in visible_columns if column in COLUMNS
        ] or list(COLUMNS)
        self.column_visible_vars: dict[str, BooleanVar] = {
            column: BooleanVar(value=column in self.visible_columns)
            for column in COLUMNS
        }

        self._build_ui()

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

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)

        toolbar = ttk.Frame(self.root, padding=(10, 8))
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.columnconfigure(10, weight=1)

        ttk.Button(toolbar, text="파일 선택", command=self.choose_files).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(toolbar, text="분석", command=self.analyze).grid(
            row=0, column=1, padx=(0, 14)
        )

        ttk.Checkbutton(
            toolbar, text="MMI", variable=self.filter_mmi_var, command=self.apply_filters
        ).grid(row=0, column=2, padx=(0, 6))
        ttk.Checkbutton(
            toolbar,
            text="SECS/GEM",
            variable=self.filter_secs_var,
            command=self.apply_filters,
        ).grid(row=0, column=3, padx=(0, 12))
        ttk.Checkbutton(
            toolbar,
            text="Setup.ini 덤프 제외",
            variable=self.skip_setup_var,
        ).grid(row=0, column=4, padx=(0, 12))

        ttk.Label(toolbar, text="포함 키워드").grid(row=0, column=5, padx=(0, 4))
        keyword_entry = ttk.Entry(toolbar, textvariable=self.keyword_var, width=24)
        keyword_entry.grid(row=0, column=6, padx=(0, 6))
        keyword_entry.bind("<Return>", lambda _event: self.add_keyword())
        ttk.Combobox(
            toolbar,
            textvariable=self.keyword_mode_var,
            values=("AND", "OR"),
            width=5,
            state="readonly",
        ).grid(row=0, column=7, padx=(0, 6))
        ttk.Button(toolbar, text="추가/수정", command=self.add_keyword).grid(
            row=0, column=8, padx=(0, 6)
        )
        ttk.Checkbutton(
            toolbar,
            text="대소문자 구분",
            variable=self.case_sensitive_var,
            command=self.apply_filters,
        ).grid(row=0, column=9, padx=(0, 12))
        ttk.Checkbutton(
            toolbar,
            text="정규식 검색",
            variable=self.regex_search_var,
            command=self.apply_filters,
        ).grid(row=1, column=8, padx=(0, 12), pady=(6, 0))
        ttk.Button(toolbar, text="검색/필터 적용", command=self.apply_filters).grid(
            row=0, column=10, sticky="w"
        )
        ttk.Label(toolbar, text="제외 키워드").grid(
            row=1, column=5, padx=(0, 4), pady=(6, 0)
        )
        exclude_keyword_entry = ttk.Entry(
            toolbar, textvariable=self.exclude_keyword_var, width=24
        )
        exclude_keyword_entry.grid(row=1, column=6, padx=(0, 6), pady=(6, 0))
        exclude_keyword_entry.bind("<Return>", lambda _event: self.add_exclude_keyword())
        ttk.Button(toolbar, text="추가", command=self.add_exclude_keyword).grid(
            row=1, column=7, padx=(0, 6), pady=(6, 0)
        )

        actions = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        actions.grid(row=1, column=0, sticky="ew")
        actions.columnconfigure(4, weight=1)
        ttk.Label(actions, text="표시 행").grid(row=0, column=0, padx=(0, 4))
        ttk.Spinbox(
            actions,
            from_=100,
            to=100000,
            increment=100,
            textvariable=self.display_rows_var,
            width=8,
            command=self.refresh_table,
        ).grid(row=0, column=1, padx=(0, 12))
        ttk.Checkbutton(
            actions,
            text="S6F11 CEID 제외",
            variable=self.exclude_s6f11_var,
            command=self.save_s6f11_exclude_settings,
        ).grid(row=0, column=2, padx=(0, 4))
        exclude_ceid_entry = ttk.Entry(actions, textvariable=self.exclude_ceid_var, width=20)
        exclude_ceid_entry.grid(row=0, column=3, padx=(0, 12))
        exclude_ceid_entry.bind(
            "<FocusOut>", lambda _event: self.save_s6f11_exclude_settings()
        )
        exclude_ceid_entry.bind(
            "<Return>", lambda _event: self.save_s6f11_exclude_settings()
        )
        ttk.Label(actions, textvariable=self.summary_var).grid(
            row=0, column=4, sticky="w"
        )
        ttk.Button(actions, text="CSV 저장", command=self.export_csv).grid(
            row=0, column=5, padx=(8, 6)
        )
        ttk.Button(actions, text="리포트 저장", command=self.export_report).grid(
            row=0, column=6, padx=(0, 6)
        )
        column_button = ttk.Menubutton(actions, text="컬럼 설정")
        column_button.grid(row=0, column=7)
        self.column_menu = Menu(column_button, tearoff=False)
        column_button["menu"] = self.column_menu
        self._build_column_menu()

        keyword_panel = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        keyword_panel.grid(row=2, column=0, sticky="ew")
        keyword_panel.columnconfigure(0, weight=1)
        keyword_panel.columnconfigure(1, weight=1)

        include_panel = ttk.Frame(keyword_panel)
        include_panel.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        include_panel.columnconfigure(0, weight=1)
        ttk.Label(include_panel, text="포함 키워드 목록 (AND / OR)").grid(
            row=0, column=0, sticky="w"
        )
        self.keyword_listbox = Listbox(
            include_panel, height=4, exportselection=False, selectmode="extended"
        )
        self.keyword_listbox.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        self.keyword_listbox.bind("<<ListboxSelect>>", self.load_selected_keyword)
        self.keyword_listbox.bind("<Delete>", self.remove_selected_keyword)
        include_buttons = ttk.Frame(include_panel)
        include_buttons.grid(row=2, column=0, sticky="e")
        ttk.Button(
            include_buttons, text="선택 삭제", command=self.remove_selected_keyword
        ).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(include_buttons, text="전체 삭제", command=self.clear_keywords).grid(
            row=0, column=1
        )

        exclude_panel = ttk.Frame(keyword_panel)
        exclude_panel.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        exclude_panel.columnconfigure(0, weight=1)
        ttk.Label(exclude_panel, text="제외 키워드 목록 (하나라도 있으면 제외)").grid(
            row=0, column=0, sticky="w"
        )
        self.exclude_keyword_listbox = Listbox(
            exclude_panel, height=4, exportselection=False, selectmode="extended"
        )
        self.exclude_keyword_listbox.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        self.exclude_keyword_listbox.bind(
            "<<ListboxSelect>>", self.load_selected_exclude_keyword
        )
        self.exclude_keyword_listbox.bind("<Delete>", self.remove_selected_exclude_keyword)
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

        drop_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        drop_frame.grid(row=3, column=0, sticky="ew")
        drop_frame.columnconfigure(0, weight=1)
        drop_text = (
            "로그 파일을 여기에 드래그앤드롭하면 목록에 추가됩니다."
            if TkinterDnD is not None
            else "드래그앤드롭을 사용하려면 tkinterdnd2 패키지가 필요합니다. 파일 선택 버튼은 사용할 수 있습니다."
        )
        self.drop_label = ttk.Label(
            drop_frame,
            text=drop_text,
            relief="groove",
            anchor="center",
            padding=(10, 8),
        )
        self.drop_label.grid(row=0, column=0, sticky="ew")

        self.content_pane = ttk.PanedWindow(self.root, orient="vertical")
        self.content_pane.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 8))

        table_frame = ttk.Frame(self.content_pane)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            table_frame,
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
        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_detail)
        self.content_pane.add(table_frame, weight=4)

        detail_frame = ttk.Frame(self.content_pane)
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(2, weight=1)
        self.splitter_grip = Canvas(
            detail_frame,
            height=16,
            highlightthickness=0,
            bd=0,
            cursor="sb_v_double_arrow",
            background="#e5e7eb",
        )
        self.splitter_grip.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.splitter_grip.bind("<Configure>", self._draw_splitter_grip)
        self.splitter_grip.bind("<B1-Motion>", self._drag_main_splitter)
        detail_header = ttk.Frame(detail_frame)
        detail_header.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        detail_header.columnconfigure(0, weight=1)
        ttk.Label(detail_header, text="선택 로그 상세").grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(
            detail_header,
            text="상세 세로 분할",
            variable=self.detail_vertical_var,
            command=self.show_selected_detail,
        ).grid(row=0, column=1, padx=(8, 0))
        ttk.Checkbutton(
            detail_header,
            text="긴 로그 줄바꿈",
            variable=self.detail_wrap_var,
            command=self.show_selected_detail,
        ).grid(row=0, column=2, padx=(8, 0))
        self.detail_pane_container = ttk.Frame(detail_frame)
        self.detail_pane_container.grid(row=2, column=0, sticky="nsew")
        self.detail_pane_container.columnconfigure(0, weight=1)
        self.detail_pane_container.rowconfigure(0, weight=1)
        self.detail_pane = ttk.PanedWindow(
            self.detail_pane_container,
            orient="vertical",
        )
        self.detail_pane.grid(row=0, column=0, sticky="nsew")
        self.content_pane.add(detail_frame, weight=1)

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
            mode="indeterminate",
            length=220,
        )
        self.progress.grid(row=0, column=1, sticky="e", padx=(8, 10))
        self._setup_drag_and_drop()

    def _load_settings(self) -> dict:
        try:
            if APP_CONFIG_PATH.exists():
                data = json.loads(APP_CONFIG_PATH.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            return {}
        return {}

    def _save_settings(self) -> None:
        self.settings["visible_columns"] = self.visible_columns
        self.settings["exclude_s6f11_enabled"] = self.exclude_s6f11_var.get()
        self.settings["exclude_s6f11_ceid_ranges"] = self.exclude_ceid_var.get().strip()
        APP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        APP_CONFIG_PATH.write_text(
            json.dumps(self.settings, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def save_s6f11_exclude_settings(self) -> None:
        self._save_settings()
        self.status_var.set(f"S6F11 제외 설정 저장됨: {APP_CONFIG_PATH}")

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

    def show_all_columns(self) -> None:
        for variable in self.column_visible_vars.values():
            variable.set(True)
        self.visible_columns = list(COLUMNS)
        self._apply_visible_columns(save=True)

    def _draw_splitter_grip(self, event=None) -> None:
        canvas = self.splitter_grip
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        canvas.delete("all")
        center_y = height // 2
        canvas.create_line(0, center_y, width, center_y, fill="#94a3b8", width=1)
        start_x = max(0, width // 2 - 28)
        for offset in range(0, 57, 8):
            canvas.create_oval(
                start_x + offset,
                center_y - 2,
                start_x + offset + 4,
                center_y + 2,
                fill="#475569",
                outline="",
            )

    def _drag_main_splitter(self, event) -> str:
        y = event.y_root - self.content_pane.winfo_rooty()
        min_y = 120
        max_y = max(min_y, self.content_pane.winfo_height() - 120)
        self.content_pane.sashpos(0, max(min_y, min(y, max_y)))
        return "break"

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
        selected = list(self.keyword_listbox.curselection())
        if len(selected) == 1:
            index = selected[0]
            self.keywords[index] = (mode, keyword)
            self.keyword_listbox.delete(index)
            self.keyword_listbox.insert(index, self._keyword_label(mode, keyword))
            self.keyword_listbox.selection_clear(0, "end")
        elif (mode, keyword) not in self.keywords:
            self.keywords.append((mode, keyword))
            self.keyword_listbox.insert("end", self._keyword_label(mode, keyword))
        self.keyword_var.set("")
        self.apply_filters()

    def load_selected_keyword(self, _event=None) -> None:
        selected = list(self.keyword_listbox.curselection())
        if len(selected) != 1:
            return
        mode, keyword = self.keywords[selected[0]]
        self.keyword_mode_var.set(mode)
        self.keyword_var.set(keyword)

    def remove_selected_keyword(self, _event=None) -> str | None:
        selected = list(self.keyword_listbox.curselection())
        if not selected:
            return None
        for index in reversed(selected):
            del self.keywords[index]
            self.keyword_listbox.delete(index)
        self.keyword_var.set("")
        self.apply_filters()
        return "break"

    def clear_keywords(self) -> None:
        self.keywords.clear()
        self.keyword_listbox.delete(0, "end")
        self.keyword_var.set("")
        self.apply_filters()

    def _keyword_label(self, mode: str, keyword: str) -> str:
        return f"[{mode}] {keyword}"

    def add_exclude_keyword(self) -> None:
        keyword = self.exclude_keyword_var.get().strip()
        if not keyword:
            return
        selected = list(self.exclude_keyword_listbox.curselection())
        if len(selected) == 1:
            index = selected[0]
            self.exclude_keywords[index] = keyword
            self.exclude_keyword_listbox.delete(index)
            self.exclude_keyword_listbox.insert(index, keyword)
            self.exclude_keyword_listbox.selection_clear(0, "end")
        elif keyword not in self.exclude_keywords:
            self.exclude_keywords.append(keyword)
            self.exclude_keyword_listbox.insert("end", keyword)
        self.exclude_keyword_var.set("")
        self.apply_filters()

    def load_selected_exclude_keyword(self, _event=None) -> None:
        selected = list(self.exclude_keyword_listbox.curselection())
        if len(selected) != 1:
            return
        self.exclude_keyword_var.set(self.exclude_keywords[selected[0]])

    def remove_selected_exclude_keyword(self, _event=None) -> str | None:
        selected = list(self.exclude_keyword_listbox.curselection())
        if not selected:
            return None
        for index in reversed(selected):
            del self.exclude_keywords[index]
            self.exclude_keyword_listbox.delete(index)
        self.exclude_keyword_var.set("")
        self.apply_filters()
        return "break"

    def clear_exclude_keywords(self) -> None:
        self.exclude_keywords.clear()
        self.exclude_keyword_listbox.delete(0, "end")
        self.exclude_keyword_var.set("")
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
        self.status_var.set("로그 로딩 중... 파일 파싱 및 DB 매핑 조회를 진행하고 있습니다.")
        self._set_controls_busy(True)
        self.progress.start(12)
        worker = threading.Thread(
            target=self._analyze_worker,
            args=(excluded_ranges,),
            daemon=True,
        )
        worker.start()

    def _excluded_ceid_ranges(self) -> tuple[tuple[int, int], ...]:
        if not self.exclude_s6f11_var.get():
            return ()
        text = self.exclude_ceid_var.get().strip()
        if not text:
            return ()

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
        return tuple(ranges)

    def _analyze_worker(self, excluded_ranges: tuple[tuple[int, int], ...]) -> None:
        try:
            entries, skipped, file_types = parse_paths(
                self.paths,
                skip_setup_dump=self.skip_setup_var.get(),
                excluded_s6f11_ceid_ranges=excluded_ranges,
            )
            mapped_count, lookup_error = self._attach_event_names(entries)
            report_variables, report_variable_count, report_variable_error = (
                self._load_report_variables(entries)
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
                ),
            )
        except Exception:
            error = traceback.format_exc()
            self.root.after(0, lambda: self._analysis_failed(error))

    def _attach_event_names(self, entries: list[LogEntry]) -> tuple[int, str | None]:
        ceids = sorted({entry.ceid for entry in entries if entry.ceid is not None})
        if not ceids:
            return 0, None
        try:
            names = load_event_names(ceids)
        except Exception as exc:
            return 0, str(exc)
        for entry in entries:
            if entry.ceid is not None:
                entry.event_name = names.get(entry.ceid)
        return len(names), None

    def _load_report_variables(
        self, entries: list[LogEntry]
    ) -> tuple[dict[int, list[ReportVariable]], int, str | None]:
        rptids: set[int] = set()
        for entry in entries:
            rptids.update(extract_s6f11_rptids(entry.message))
        if not rptids:
            return {}, 0, None
        try:
            report_variables = load_report_variables(rptids)
        except Exception as exc:
            return {}, 0, str(exc)
        return report_variables, sum(len(items) for items in report_variables.values()), None

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
    ) -> None:
        self.entries = entries
        self.skipped_setup_lines = skipped
        self.file_types = file_types
        self.gem300_events = gem300_events
        self.alarms = alarms
        self.report_variables = report_variables
        self.progress.stop()
        self._set_controls_busy(False)
        ceid_count = sum(1 for entry in entries if entry.ceid is not None)
        lookup_text = (
            f" CEID 이벤트명 {mapped_count}개 매핑."
            if not lookup_error
            else f" 이벤트명 조회 실패: {lookup_error}"
        )
        report_variable_text = (
            f" Report VID {report_variable_count}개 매핑."
            if not report_variable_error
            else f" Report VID 조회 실패: {report_variable_error}"
        )
        self.status_var.set(
            f"분석 완료. 전체 {len(entries)}건, S6F11 CEID {ceid_count}건."
            f"{lookup_text}{report_variable_text}"
        )
        self.apply_filters()

    def _analysis_failed(self, error: str) -> None:
        self.progress.stop()
        self._set_controls_busy(False)
        self.status_var.set("분석 실패")
        messagebox.showerror("분석 실패", error)

    def _set_controls_busy(self, busy: bool) -> None:
        cursor = "watch" if busy else ""
        self.root.configure(cursor=cursor)

    def apply_filters(self) -> None:
        selected_types: set[str] = set()
        if self.filter_mmi_var.get():
            selected_types.add("MMI")
        if self.filter_secs_var.get():
            selected_types.add("SECS")

        base_entries = [
            entry for entry in self.entries if entry.log_type.value in selected_types
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

    def refresh_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        rows = self.filtered_entries[: max(1, self.display_rows_var.get())]
        for index, entry in enumerate(rows):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=_entry_to_values(
                    entry,
                    self.matched_keywords_by_entry.get(id(entry), ""),
                ),
            )
        hidden = max(0, len(self.filtered_entries) - len(rows))
        self.summary_var.set(
            f"표시 {len(rows)}건 / 필터 결과 {len(self.filtered_entries)}건"
            + (f" ({hidden}건 더 있음)" if hidden else "")
        )
        self._clear_detail()

    def show_selected_detail(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            self._clear_detail()
            return
        selected_indices = sorted(
            int(item) for item in selected if item.isdigit()
        )
        selected_indices = [
            index for index in selected_indices if index < len(self.filtered_entries)
        ]
        if not selected_indices:
            self._clear_detail()
            return
        self._clear_detail()
        orient = "vertical" if self.detail_vertical_var.get() else "horizontal"
        self.detail_pane = ttk.PanedWindow(self.detail_pane_container, orient=orient)
        self.detail_pane.grid(row=0, column=0, sticky="nsew")

        for index in selected_indices[:8]:
            entry = self.filtered_entries[index]
            pane = self._create_detail_pane(entry, index)
            self.detail_pane.add(pane, weight=1)

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
        detail_text = Text(body, wrap=wrap, height=8, undo=False)
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

        message = annotate_s6f11_variables(entry.message, self.report_variables)
        message = _format_xml_in_message(message)
        rows = [
            ("시간", entry.display_time),
            ("로그타입", entry.log_type.value),
            ("매칭 키워드", self.matched_keywords_by_entry.get(id(entry), "")),
            ("레벨", entry.level_name or ""),
            ("채널", "" if entry.channel is None else str(entry.channel)),
            ("CEID", "" if entry.ceid is None else str(entry.ceid)),
            ("이벤트명", entry.event_name or ""),
            ("파일", entry.source_file),
            ("라인", str(entry.line_no)),
            ("메시지", message),
        ]
        detail_text.insert("1.0", "\n".join(f"{field}: {value}" for field, value in rows))
        return pane

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

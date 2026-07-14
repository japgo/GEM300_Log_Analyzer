# GEM300 Log Analyzer 소스 요약

이 문서는 토큰 절약을 위해 현재 소스 구조와 주요 흐름을 압축 정리한 개발용 메모다.
새 작업을 시작할 때는 우선 `FEATURE_SPEC.md`와 이 파일을 읽으면 전체 맥락을 빠르게 잡을 수 있다.

## 운영 기준

- 현재 개발 기준 UI는 `desktop_app.py`의 Tkinter 데스크톱 앱이다.
- `app.py`는 Streamlit 버전이며, 별도 요청이 있을 때만 수정한다.
- 파싱 로직을 바꾸지 않았다면 보통 `tests/verify_parsing.py` 실행은 생략한다.
- UI/스타일/배치 변경은 보통 `python -m py_compile desktop_app.py`로 문법 검증한다.
- 배포 파일 생성은 사용자가 명시적으로 요청할 때만 한다.
- 루트 `wheels`는 용량 최적화를 위해 Windows 64-bit Python 3.14 전용 wheel만 포함한다. Python/ODBC 설치 파일은 포함하지 않는다.
- 버전은 `gem300_log_analyzer.__version__`에서 관리하고, 데스크톱 창 제목에 `vX.Y.Z`로 표시한다. 현재 버전은 `v1.6.6`이다.

## 전체 구조

```text
desktop_app.py                         # 메인 데스크톱 UI, 상태 관리, 필터/상세/내보내기
app.py                                 # Streamlit UI 엔트리
src/gem300_log_analyzer/models.py      # 공통 데이터 모델
src/gem300_log_analyzer/parsers/       # MMI/SECS 파싱 및 파일 로딩
src/gem300_log_analyzer/analysis/      # 키워드, GEM300 이벤트, 알람, S6F11 변수, Carrier roundtrip 분석
src/gem300_log_analyzer/db/            # SQL Server 기준 CEID/Event/RPT 변수 조회
src/gem300_log_analyzer/export/        # Markdown/TXT 리포트 생성
config/level_map.yaml                  # MMI color index -> level 이름 매핑
tests/verify_parsing.py                # 샘플/fixture 기반 파싱 검증 스크립트
```

## 핵심 데이터 모델

`models.py`가 앱 전체의 공통 구조를 정의한다.

- `LogType`: `MMI`, `SECS`, `UNKNOWN`
- `LogEntry`: 통합 로그의 기본 단위. 시간, 타입, 파일명, 메시지, 라인 번호, MMI level, SECS channel, CEID, event name, repeat count, 원본 로그 라인(`raw_line`) 등을 가진다.
- `Gem300Event`: MMI 로그에서 추출한 GEM300 상태/객체 이벤트. Carrier roundtrip용 `carrier_id`, `id_read`, `slotmap_read`, `port_no`, `seq_port_no`, `mmi_port_no`, `loc_id` 구조화 필드를 가진다.
- `AlarmRecord`: 알람 요약용 레코드.
- `SearchMatch`: 검색 결과와 매칭 키워드.
- `AnalysisResult`: 엔트리, 이벤트, 알람, 검색 결과를 묶는 결과 컨테이너.

## 파싱 흐름

메인 로딩 함수는 `parsers/log_loader.py`에 있다.

1. 파일 내용을 UTF-8 `errors="replace"`로 읽는다.
2. `detect_log_type()`이 MMI/SECS 형식을 판별한다.
3. MMI는 `parse_mmi_log()`, SECS는 `parse_secs_log()`로 `LogEntry` 목록을 만든다.
4. DB 참조 데이터가 있으면 CEID event name과 S6F11 report variable 주석을 붙인다.
5. 모든 파일 결과를 시간순으로 정렬한다.
6. 같은 timestamp면 MMI가 SECS보다 먼저 오도록 `_timeline_sort_key()`가 우선순위를 준다.

`parse_paths()`는 여러 파일을 `ThreadPoolExecutor`로 병렬 파싱하며, 진행률 콜백에는 파일명과 라인 수를 넘긴다. 대용량 로그 안정성을 위해 기본/최대 worker 수는 8개로 제한한다.

## MMI 파서

`parsers/mmi_parser.py`

- 기본 라인 형식: `YYYY-MM-DD HH:MM:SS:mmm|COLOR|SEQ|MESSAGE`
- `config/level_map.yaml`로 color index를 level 이름으로 변환한다.
- `-->[Count:n]` suffix를 `repeat_count`로 분리한다.
- `[*.ini] LOGGING`부터 `[*.ini] FINISH` 사이의 Setup.ini 덤프를 옵션에 따라 제외한다.
- 다음 timestamp 라인이 나오기 전까지 이어지는 비정형 줄은 이전 메시지와 `raw_line`에 붙인다.

## SECS 파서

`parsers/secs_parser.py`

- 기본 라인 형식: `HH:MM:SS:mmm: [channel] MESSAGE`
- 날짜는 파일명 안의 `YYYY-MM-DD`를 우선 사용하고, 없으면 오늘 날짜를 사용한다.
- 들여쓰기된 후속 줄은 이전 SECS 메시지와 `raw_line`에 붙여 multi-line 원문 복사를 보존한다.
- S6F11 메시지에서 CEID를 추출한다.
  - `CEID = n` inline 형식 우선
  - 아니면 SECS value 목록의 두 번째 숫자를 CEID로 본다.
- 제외 CEID range에 해당하는 S6F11은 로딩 단계에서 버린다.

## 분석 모듈

`analysis/keyword_search.py`

- 포함 키워드, OR 키워드, 제외 키워드, AND/OR 조건을 처리한다.
- 정규식/일반 문자열 검색과 대소문자 옵션을 지원한다.
- `SxFyW`는 검색상 `SxFy`와 같게 보도록 정규화한다.

`analysis/gem300_trace.py`

- MMI 로그에서 GEM300 관련 패턴을 추출한다.
- 현재 주요 패턴: `CarrierObject::StateChange`, `CarrierObject::ClearCarrierInfo`, `LoadPortObject::StateChange`, `SubstrateObject::Initialize`, `[CMS]`, `DeletejobList`

`analysis/alarm_summary.py`

- MMI color index 31, level name `Alarm`, `[ALARM]`, `Alarm Code` 등을 알람으로 본다.
- `Alarm Code [n]`이 있으면 code를 추출한다.
- `repeat_count`가 있으면 요약 count에 반영한다.

`analysis/s6f11_variables.py`

- 들여쓰기 기반으로 SECS item tree를 가볍게 파싱한다.
- S6F11 body의 CEID value line에 Events 이벤트명 주석을 붙이고, report list에서 RPTID를 추출한다.
- DB에서 가져온 `ReportVariable` 목록과 value node를 순서대로 매칭해 메시지 라인 끝에 `// (VID) name` 주석을 붙인다.

## DB 연동

`db/event_lookup.py`

- `pyodbc`로 SQL Server에 접속한다.
- 기본값: driver `ODBC Driver 17 for SQL Server`, server `localhost`, database `BOCCOB_BONDER`
- `Events` 테이블에서 CEID와 이벤트명을 조회한다.
- database 목록 조회와 event 검색 기능도 제공한다.

`db/report_variable_lookup.py`

- `ReportVariables`와 `Variables`를 조인해 RPTID별 VID/name 목록을 조회한다.
- 결과는 `dict[int, list[ReportVariable]]` 형태다.

## 데스크톱 앱 구조

`desktop_app.py`의 `Gem300DesktopApp` 한 클래스가 대부분의 UI와 상태를 담당한다.

- 앱 시작 시 메인 창을 잠시 숨기고 시작 로딩 화면을 먼저 표시한 뒤 UI 생성 완료 후 메인 창을 보여준다.
- 다크 테마는 VS Code Dark 회색 계열 색상(`#1e1e1e`, `#252526`, `#3a3d41`)을 기준으로 하며, 입력 커서/메뉴 체크 표시/hover 상태도 다크 색상으로 보정한다.

주요 상태:

- 파일 경로: `self.paths`
- 전체 로그: `self.entries`
- 필터 결과: `self.filtered_entries`
- 검색 결과: `self.search_matches`
- 매칭 키워드 lookup: `self.matched_keywords_by_entry`
- GEM300 이벤트/알람: `self.gem300_events`, `self.alarms`
- Carrier roundtrip: `self.carrier_roundtrip_rows`, `self.roundtrip_row_refs`, `self.carrier_roundtrip_var`
- 북마크/메모: `self.bookmarks`
- 북마크 버튼 동작 후 `_focus_result_table()`로 결과 테이블 키보드 포커스를 복원한다.
- 시간 필터: `self.time_filter_start`, `self.time_filter_end`
- 직접 시간 지정: `open_custom_time_filter_dialog()`가 시작/종료 입력을 받고 `_parse_custom_time_filter_inputs()`가 날짜 포함/시간만 입력을 해석한다.
- SxFy 필터: `self.sxfy_types`, `self.sxfy_filter_vars`
- DB 설정/주석 옵션, S6F11 제외 CEID 설정, 컬럼 표시/순서, 상세 보기 옵션 등

주요 UI 영역:

- `Carrier Roundtrip Timeline`: 현재 `CARRIER_ROUNDTRIP_TIMELINE_ENABLED = False`로 기본 숨김 처리되어 있다. 재작업 시 Carrier ID 시간순 상태 변화, row 클릭 원본 로그 이동, 상세 로그 영역 resize 회귀를 함께 검증해야 한다.

- 상단 toolbar: 파일 선택, 분석, 초기화, 세션 저장/복원, 내보내기
- 빠른 검색/필터 영역: 포함/제외 키워드, AND/OR, SxFy, 로그 타입, 북마크, 시간 필터
- 옵션 notebook: 검색 옵션, DB 주석, 컬럼, 상세 보기, 테마 등
- 결과 table: `ttk.Treeview`
- 선택 로그 원문 복사: 결과 table 다중 선택 후 우클릭 `선택 로그 원문 복사`로 원본 시간 prefix를 유지하면서 상세 로그의 CEID/VID 주석이 포함된 `LogEntry.message`를 빈 줄 구분해 클립보드에 넣는다. `raw_line`이 없는 테스트/레거시 entry는 `message`로 fallback한다.
- 북마크 타임라인 panel
- 통계 panel
- 상세 보기/비교 보기 panel
- 하단 progress/status

## 데스크톱 앱 주요 흐름

분석:

1. `analyze()`가 선택 파일과 옵션을 확인한다.
2. 분석 시작 전 `_disable_bookmark_only_for_analysis()`가 북마크만 보기 필터를 해제한다.
3. `_analyze_worker()`가 별도 thread에서 파일 라인 수를 chunk 단위로 계산하고 `parse_paths()`를 호출한다.
4. DB 주석 옵션이 켜져 있으면 event name과 report variable을 미리 로드한다.
5. 파싱 후 GEM300 이벤트와 알람을 추출한다.
6. `_analysis_complete()`가 UI thread에서 상태를 갱신하고 필터를 적용한다.

필터:

1. `apply_filters()`가 generation 값을 증가시키고 백그라운드 필터 작업을 시작한다.
2. `_filter_worker()`/`_build_filtered_entries()`가 키워드, 제외 키워드, 로그 타입, SxFy, 북마크, 빠른/직접 지정 시간 범위, 결과 내 검색어를 적용한다.
3. `_filter_complete()`가 최신 generation 결과만 반영한다.
4. 북마크만 보기 해제 시 선택 로그 1개가 있으면 entry key를 보관했다가 필터 완료 후 해당 row까지 표시 범위를 확장하고 selection/focus/see를 복원한다.
5. 결과 내 검색 지우기도 같은 pending key 복원 흐름을 사용해 선택 로그 위치를 유지한다.
5. 북마크만 보기 상태의 Ctrl+Click은 앱에서 selection add/remove를 처리하고 `after_idle`에서 한 번 더 복원해, Tk 기본 Treeview anchor 처리 이후에도 최초 선택보다 위쪽 로그 클릭 시 기존 선택을 유지한다.

결과 내 검색:

- `result_search_var`는 빠른 검색 영역의 "결과 내" 입력값이다.
- 일반 필터 결과가 만들어진 뒤 `result_keyword`를 한 번 더 적용하므로, 전체 로그가 아니라 현재 결과 목록 안에서만 좁힌다.
- 결과 내 검색어는 `_highlight_terms()`에도 포함되어 상세 로그에서 같이 강조된다.
4. `refresh_table()`이 Treeview를 다시 채운다. 기존 row는 일괄 삭제하고, 통계 패널이 숨겨져 있으면 통계 재집계를 생략한다.

상세 보기:

- `show_selected_detail()`이 선택 행의 상세 내용을 표시한다.
- 비교 모드에서는 선택 행 주변 또는 선택 2개 행을 diff 형태로 보여준다.
- XML fragment는 `_format_xml_in_message()`로 pretty print를 시도한다.
- 검색어와 flow 관련 term은 Text tag로 강조한다.

세션:

- `save_session()`/`load_session()`이 JSON으로 현재 작업 상태를 저장/복원한다.
- 저장 대상에는 파일 목록, 키워드, 제외 키워드, 검색 옵션, SxFy/시간/북마크 필터, 컬럼 상태, 상세 보기 옵션, 북마크/메모, DB/S6F11 설정 등이 포함된다.

설정:

- 로컬 설정 파일은 `%LOCALAPPDATA%/GEM300LogAnalyzer/desktop_settings.json`이다.
- `desktop_settings.json`은 `utf-8-sig`로 저장하고, 기존 파일 호환을 위해 `utf-8`, `cp949` 읽기도 fallback으로 지원한다.
- 테마, 컬럼 표시/순서, 검색 preset, 북마크, DB 설정, S6F11 제외 목록, 상세 보기 옵션 등이 저장된다.

## Streamlit 앱

`app.py`는 웹/Streamlit 버전이다.

- 파일 업로드 기반으로 동작한다.
- `parse_uploaded_files()`를 사용한다.
- 키워드 검색, 로그 타입 필터, 시간 범위, S6F11 CEID 제외, event name 조회, GEM300 timeline, 알람 요약, report download를 제공한다.
- 현재 문서/출력 일부가 인코딩 깨짐처럼 보일 수 있다. 데스크톱 앱이 기준이므로 별도 요청 없이는 건드리지 않는다.

## 리포트/내보내기

`export/report_export.py`

- `generate_report()`가 Markdown 또는 plain text 스타일의 문자열을 만든다.
- 포함 내용: 생성 시각, 총 parsed entry 수, MMI/SECS 수, skipped Setup.ini line 수, 파일 요약, 알람 요약, GEM300 state timeline, 키워드 검색 결과

`desktop_app.py`에는 CSV export와 report export UI가 별도로 있다.

## 실행 스크립트

- `run_desktop.bat`는 `src/run_desktop.vbs`를 통해 PowerShell을 hidden으로 실행한다.
- `src/run_desktop.ps1`은 venv 생성/패키지 설치 후 가능하면 `pythonw.exe`로 데스크톱 앱을 실행해 콘솔창 노출을 줄인다.
- `src/build_exe.ps1`은 wheelhouse에서 PyInstaller를 설치하고 `src/dist/GEM300_Log_Analyzer_vX.Y.Z.exe`를 생성한다.

## 테스트/검증

`tests/verify_parsing.py`

- 실제 백업 로그 경로가 있으면 그것을 쓰고, 없으면 fixture 경로를 찾는다.
- 검증 항목: entry 존재, 통합 timeline 정렬, 같은 timestamp의 MMI 우선, MMI/SECS 존재, GEM300 이벤트, 키워드 매칭, report 내용
- 현재 저장소에 `tests/fixtures` 파일은 보이지 않는다. 샘플 경로도 환경 의존적이므로 테스트 실행 전 fixture 존재 여부를 확인해야 한다.

## 수정 시 주의점

- 파싱 결과 정렬 규칙은 사용자 기능에 직접 영향을 준다. 같은 timestamp의 MMI 우선 규칙을 유지한다.
- S6F11 CEID 제외는 성능 최적화 성격이 강하므로 로딩 단계에서 처리하는 현재 구조를 유지하는 편이 좋다.
- `desktop_app.py`는 큰 단일 클래스다. 작은 UI 수정은 기존 메서드 근처에서 최소 변경하는 것이 안전하다.
- 백그라운드 작업 결과는 UI thread에서 반영해야 한다. Tkinter 위젯을 worker thread에서 직접 만지지 않는다.
- 필터는 generation guard가 있으므로 비동기 결과를 추가할 때 최신 generation 확인 흐름을 유지한다.
- DB 조회는 실패 가능성이 높다. UI에서는 예외를 사용자 메시지로 보여주고 앱 전체 흐름은 유지하는 방식이 맞다.
- Streamlit 쪽 텍스트는 일부 깨져 보인다. 데스크톱 기준 작업에서는 불필요한 수정으로 번지지 않게 한다.

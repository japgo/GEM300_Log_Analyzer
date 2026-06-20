"""Streamlit entry point for GEM300 log analyzer."""

from __future__ import annotations

import sys
from datetime import datetime, time
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gem300_log_analyzer.analysis.alarm_summary import extract_alarms, summarize_alarms
from gem300_log_analyzer.analysis.gem300_trace import extract_gem300_events
from gem300_log_analyzer.analysis.keyword_search import search_keywords
from gem300_log_analyzer.db.event_lookup import load_event_names
from gem300_log_analyzer.export.report_export import generate_report
from gem300_log_analyzer.parsers.log_loader import parse_uploaded_files


def _parse_time_range(
    use_filter: bool,
    start_date,
    start_time: time,
    end_date,
    end_time: time,
) -> tuple[datetime | None, datetime | None]:
    if not use_filter:
        return None, None
    start = datetime.combine(start_date, start_time)
    end = datetime.combine(end_date, end_time)
    return start, end


def _entries_to_df(entries, max_rows: int = 500) -> pd.DataFrame:
    rows = []
    for entry in entries[:max_rows]:
        rows.append(
            {
                "시간": entry.display_time,
                "로그타입": entry.log_type.value,
                "레벨/채널": entry.level_name
                or (f"CH {entry.channel}" if entry.channel is not None else ""),
                "CEID": entry.ceid or "",
                "이벤트명": entry.event_name or "",
                "파일": entry.source_file,
                "라인": entry.line_no,
                "메시지": entry.message[:500],
            }
        )
    return pd.DataFrame(rows)


def _gem300_to_df(events) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "시간": e.timestamp.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3],
                "이벤트": e.event_type,
                "객체": e.object_name,
                "상세": e.details,
                "파일": e.source_file,
                "라인": e.line_no,
            }
            for e in events
        ]
    )


def _alarms_to_df(alarms) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "시간": a.timestamp.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3],
                "알람코드": a.alarm_code or "",
                "메시지": a.message,
                "반복": a.repeat_count or 1,
                "파일": a.source_file,
                "라인": a.line_no,
            }
            for a in alarms
        ]
    )


@st.cache_data(show_spinner=False)
def _load_event_names_cached(ceids: tuple[int, ...]) -> dict[int, str]:
    return load_event_names(ceids)


def _attach_event_names(entries) -> tuple[int, str | None]:
    ceids = tuple(sorted({entry.ceid for entry in entries if entry.ceid is not None}))
    if not ceids:
        return 0, None

    try:
        event_names = _load_event_names_cached(ceids)
    except Exception as exc:
        return 0, str(exc)

    for entry in entries:
        if entry.ceid is not None:
            entry.event_name = event_names.get(entry.ceid)
    return len(event_names), None


def main() -> None:
    st.set_page_config(
        page_title="GEM300 Log Analyzer",
        page_icon="📋",
        layout="wide",
    )

    st.title("GEM300 Log Analyzer")
    st.caption("MMI 메인 로그 및 SECS/GEM 로그 통합 분석 도구")

    with st.sidebar:
        st.header("설정")
        skip_setup = st.toggle("INI 설정 덤프 건너뛰기 (Setup/Secsgem.ini)", value=True)
        keyword = st.text_input("키워드 검색 (정규식 지원)", value="")
        case_sensitive = st.checkbox("대소문자 구분", value=False)

        st.subheader("로그 유형 필터")
        filter_mmi = st.checkbox("MMI", value=True)
        filter_secs = st.checkbox("SECS", value=True)

        st.subheader("시간 범위")
        use_time_filter = st.checkbox("시간 필터 사용", value=False)
        filter_timeline_by_keyword = st.checkbox(
            "키워드 입력 시 통합 타임라인도 필터링",
            value=True,
        )
        timeline_rows = st.number_input(
            "통합 타임라인 표시 행",
            min_value=100,
            max_value=100000,
            value=5000,
            step=100,
        )

    uploaded = st.file_uploader(
        "로그 파일 업로드 (복수 선택 가능)",
        type=["log", "txt"],
        accept_multiple_files=True,
    )

    if not uploaded:
        st.info("분석할 `.log` 파일을 업로드하세요. MMI 로그와 SECS 로그를 함께 선택할 수 있습니다.")
        st.markdown(
            """
**지원 형식**
- MMI: `2026_06_19.log` — `YYYY-MM-DD HH:MM:SS:mmm|COLOR|SEQ| MESSAGE`
- SECS: `2026-06-19 18.log` — `HH:MM:SS:mmm: [channel] SxFy...`

**실행 방법**
```bash
pip install -r requirements.txt
streamlit run app.py
```
"""
        )
        return

    files = [(f.name, f.getvalue()) for f in uploaded]
    entries, skipped_setup, file_types = parse_uploaded_files(
        files,
        skip_setup_dump=skip_setup,
    )

    if not entries:
        st.warning("파싱된 로그 항목이 없습니다. 파일 형식을 확인하세요.")
        return

    loaded_event_count, event_lookup_error = _attach_event_names(entries)

    min_ts = min(e.timestamp for e in entries)
    max_ts = max(e.timestamp for e in entries)

    with st.sidebar:
        if use_time_filter:
            start_date = st.date_input("시작 날짜", value=min_ts.date())
            start_time = st.time_input("시작 시간", value=min_ts.time())
            end_date = st.date_input("종료 날짜", value=max_ts.date())
            end_time = st.time_input("종료 시간", value=max_ts.time())
        else:
            start_date = end_date = min_ts.date()
            start_time = end_time = time(0, 0)

    start_dt, end_dt = _parse_time_range(
        use_time_filter, start_date, start_time, end_date, end_time
    )

    log_types: set[str] = set()
    if filter_mmi:
        log_types.add("MMI")
    if filter_secs:
        log_types.add("SECS")

    filtered_entries = [
        e
        for e in entries
        if e.log_type.value in log_types
        and (start_dt is None or e.timestamp >= start_dt)
        and (end_dt is None or e.timestamp <= end_dt)
    ]

    search_matches = search_keywords(
        filtered_entries,
        keyword,
        case_sensitive=case_sensitive,
        log_types=log_types,
        start=start_dt,
        end=end_dt,
    )
    gem300_events = extract_gem300_events(filtered_entries)
    alarms = extract_alarms(filtered_entries, start=start_dt, end=end_dt)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("전체 항목", len(filtered_entries))
    col2.metric("GEM300 이벤트", len(gem300_events))
    col3.metric("알람", len(alarms))
    col4.metric("키워드 매치", len(search_matches) if keyword else "—")

    with st.expander("업로드 파일 정보", expanded=False):
        for name, detected in file_types.items():
            st.write(f"- **{name}** → {detected.value}")
        st.write(
            f"- 파싱 항목: MMI **{sum(1 for e in entries if e.log_type.value == 'MMI')}**건, "
            f"SECS/GEM **{sum(1 for e in entries if e.log_type.value == 'SECS')}**건"
        )
        ceid_count = sum(1 for e in entries if e.ceid is not None)
        st.write(f"- S6F11 CEID 감지: **{ceid_count}**건")
        if event_lookup_error:
            st.warning(f"Events 테이블 조회 실패: {event_lookup_error}")
        elif ceid_count:
            st.write(f"- Events 테이블 이벤트명 매핑: **{loaded_event_count}**개 CEID")
        if skip_setup and skipped_setup:
            st.write(f"- Setup.ini 덤프 건너뛴 라인: **{skipped_setup}**")
        st.write(f"- 시간 범위: {min_ts} ~ {max_ts}")

    tab_timeline, tab_search, tab_gem300, tab_alarm, tab_report = st.tabs(
        ["통합 타임라인", "검색 결과", "GEM300 상태 타임라인", "알람 요약", "리포트보내기"]
    )

    with tab_timeline:
        st.subheader("MMI + SECS/GEM 통합 타임라인")
        timeline_entries = filtered_entries
        if keyword and filter_timeline_by_keyword:
            timeline_entries = [m.entry for m in search_matches]
            st.info(f"'{keyword}' 검색 결과 **{len(timeline_entries)}**건을 시간순으로 표시합니다.")
        elif keyword:
            st.info(
                f"'{keyword}' 검색 결과는 **{len(search_matches)}**건입니다. "
                "검색 결과 탭에서 확인할 수 있습니다."
            )
        st.dataframe(
            _entries_to_df(timeline_entries, int(timeline_rows)),
            width="stretch",
            hide_index=True,
        )

    with tab_search:
        st.subheader("키워드 검색 결과")
        if not keyword:
            st.info("사이드바에서 키워드를 입력하세요.")
            st.dataframe(
                _entries_to_df(filtered_entries, min(int(timeline_rows), 1000)),
                width="stretch",
                hide_index=True,
            )
        elif not search_matches:
            st.warning(f"'{keyword}' 에 대한 검색 결과가 없습니다.")
        else:
            st.write(f"총 **{len(search_matches)}**건 매치")
            st.dataframe(
                _entries_to_df([m.entry for m in search_matches], int(timeline_rows)),
                width="stretch",
                hide_index=True,
            )

    with tab_gem300:
        st.subheader("GEM300 객체 상태 변경 추적")
        if not gem300_events:
            st.info("GEM300 관련 이벤트가 없습니다.")
        else:
            event_types = sorted({e.event_type for e in gem300_events})
            selected_types = st.multiselect(
                "이벤트 유형 필터",
                options=event_types,
                default=event_types,
            )
            shown = [e for e in gem300_events if e.event_type in selected_types]
            st.dataframe(_gem300_to_df(shown), width="stretch")

            st.subheader("이벤트 유형별 통계")
            type_counts = pd.Series(
                [e.event_type for e in gem300_events]
            ).value_counts()
            st.bar_chart(type_counts)

    with tab_alarm:
        st.subheader("알람 요약")
        if not alarms:
            st.success("알람이 감지되지 않았습니다.")
        else:
            summary = summarize_alarms(alarms)
            st.write("**알람 코드/메시지별 집계**")
            summary_df = pd.DataFrame(
                [{"항목": k, "횟수": v} for k, v in summary.items()]
            )
            st.dataframe(summary_df, width="stretch")
            st.dataframe(_alarms_to_df(alarms), width="stretch")

    with tab_report:
        st.subheader("리포트보내기")
        report_format = st.radio("형식", ["Markdown", "TXT"], horizontal=True)
        fmt = "markdown" if report_format == "Markdown" else "txt"
        file_types_str = {k: v.value for k, v in file_types.items()}

        report_text = generate_report(
            filtered_entries,
            gem300_events,
            alarms,
            search_matches,
            keyword=keyword,
            skipped_setup_lines=skipped_setup,
            file_summary=file_types_str,
            format=fmt,
        )

        st.download_button(
            label="리포트 다운로드",
            data=report_text,
            file_name=f"gem300_report.{ 'md' if fmt == 'markdown' else 'txt'}",
            mime="text/plain",
        )
        with st.expander("미리보기"):
            st.text(report_text[:8000])


if __name__ == "__main__":
    main()

# GEM300 Log Analyzer

GEM300 장비의 MMI 메인 로그와 SECS/GEM 통신 로그를 통합 분석하는 웹 도구입니다.

## 주요 기능

- **키워드 검색**: 정규식/대소문자 무시 검색 (MMI + SECS 통합)
- **GEM300 상태 추적**: CarrierObject, LoadPortObject, SubstrateObject, [CMS] 이벤트 타임라인
- **알람 요약**: 알람 코드별 집계 및 상세 목록
- **리포트보내기**: Markdown 또는 TXT 형식 다운로드
- **Setup.ini 덤프 건너뛰기**: 기본 ON (대용량 설정 덤프 제외)

## 요구 사항

- Python 3.11 이상

## 설치

```bash
cd d:\01_Project\02_BOC_COB\GEM300-log-analyzer
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 실행

```bash
streamlit run app.py
```

## 검증

```bash
python tests/verify_parsing.py
```
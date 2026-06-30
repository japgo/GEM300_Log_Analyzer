# GEM300 Log Analyzer

GEM300 장비의 MMI 메인 로그와 SECS/GEM 통신 로그를 통합 분석하는 도구입니다.

## 주요 기능

- **키워드 검색**: 정규식, 대소문자 옵션, MMI/SECS 통합 검색
- **GEM300 상태 추적**: CarrierObject, LoadPortObject, SubstrateObject, CMS 이벤트 타임라인
- **알람 요약**: 알람 코드별 집계 및 상세 목록
- **리포트 내보내기**: Markdown 또는 TXT 형식 다운로드
- **Setup.ini 덤프 건너뛰기**: 기본 ON
- **S6F11 CEID 제외 로딩**: 대용량 SECS/GEM 블록 로딩 최적화

## 요구 사항

- Python 3.11 이상

## 설치

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 실행

### 데스크톱 앱

```powershell
.\run_desktop.ps1
```

또는:

```powershell
.\.venv\Scripts\python.exe desktop_app.py
```

### Streamlit 앱

```bash
streamlit run app.py
```

## 검증

```bash
python tests/verify_parsing.py
```

## 오프라인 설치 패키지

대상 PC에 Python과 SQL Server ODBC Driver가 이미 설치되어 있다는 전제로 패키지를 만든다.
Python 설치 파일과 ODBC Driver 설치 파일은 포함하지 않는다.

인터넷 가능한 PC에서 패키지 생성:

wheel은 대상 PC의 Python 버전과 호환되어야 한다. 필요하면 `-PythonCommand`로 대상과 같은 버전의 Python을 지정한다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_offline_package.ps1
# 또는
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_offline_package.ps1 -PythonCommand "C:\Path\To\python.exe"
```

오프라인 PC에서 설치:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install_offline.ps1 -CreateDesktopShortcut
```
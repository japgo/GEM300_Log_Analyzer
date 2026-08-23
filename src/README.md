# GEM300 Log Analyzer

GEM300 장비의 MMI 메인 로그와 SECS/GEM 통신 로그를 통합 분석하는 도구입니다.

## 배포 폴더 구조

사용자는 저장소를 받은 뒤 루트에서 아래 항목만 사용하면 됩니다.

```text
src
wheels
offline_install.bat
run_desktop.bat
run_desktop_mac.command
```

`wheels` 폴더는 오프라인 설치용 Python 패키지를 포함합니다. 현재 포함된 바이너리 wheel은 Windows 64-bit Python 3.14 전용입니다. Python 설치 파일과 ODBC Driver 설치 파일은 포함하지 않습니다.

## 요구 사항

- Windows 배포: Windows 64-bit Python 3.14, SQL Server ODBC Driver
- macOS 개발/테스트: Python 3.11 이상, Tkinter, unixODBC

## 오프라인 설치

인터넷이 없는 PC에서 루트 폴더의 `offline_install.bat`를 실행합니다.

```bat
offline_install.bat
```

설치 스크립트는 `src\.venv` 가상환경을 만들고, `wheels` 폴더에서만 패키지를 설치합니다.

## 실행

설치 후 루트 폴더의 `run_desktop.bat`를 실행합니다.

```bat
run_desktop.bat
```

Windows 단일 실행 파일은 GitHub의 `Releases` 페이지에서 현재 버전의
`GEM300_Log_Analyzer_vX.Y.Z.exe`를 내려받습니다. EXE 파일은 저장소 소스에
포함하지 않습니다.

## macOS 실행

Finder에서 루트의 `run_desktop_mac.command`를 더블클릭합니다. 최초 실행 시
`src/.venv`를 만들고 macOS용 패키지를 인터넷에서 설치합니다. 저장소의
`wheels` 폴더는 Windows 전용이므로 macOS 실행에는 사용하지 않습니다.

필수 시스템 패키지가 없다면 먼저 터미널에서 설치합니다.

```bash
brew install python-tk@3.12 unixodbc
```

터미널에서 직접 실행할 수도 있습니다.

```bash
./run_desktop_mac.command
```

## 주요 기능

- 키워드 검색: 정규식, 대소문자 옵션, MMI/SECS 통합 검색
- 결과 내 찾기: 필터 결과를 변경하지 않고 `F3` 이전 찾기, `F4` 다음 찾기로 일치 로그 이동
- 검색 화면 모드: 왼쪽 전체 로그와 오른쪽 필터 결과를 동시에 보고, 결과 선택 시 원본 위치로 이동
- 북마크 검색 예외: 북마크 로그를 포함/제외 키워드와 관계없이 표시하는 옵션
- 북마크 보기 크기 조절: 검색 결과와 북마크 타임라인 사이 구분선을 좌우로 드래그
- GEM300 상태 추적: CarrierObject, LoadPortObject, SubstrateObject, CMS 이벤트 타임라인
- 알람 요약: 알람 코드별 집계 및 상세 목록
- 리포트 내보내기: Markdown 또는 TXT 형식 다운로드
- Setup.ini 덤프 건너뛰기: 기본 ON
- S6F11 CEID 제외 로딩: 대용량 SECS/GEM 블록 로딩 최적화
- `.tslog` 지원: 기존 MMI/SECS 내용 형식에 따라 자동 판별 및 분석

## 개발/검증

개발 파일은 `src` 아래에 있습니다. 오프라인 설치를 완료하면 pytest도 함께 설치되므로 전체 자동 테스트를 실행할 수 있습니다.

```powershell
cd src
.\.venv\Scripts\python.exe -m pytest tests -q
```

파서 변경 시에는 별도 파싱 검증도 실행합니다.

```powershell
cd src
.\.venv\Scripts\python.exe tests\verify_parsing.py
```

wheel은 대상 PC의 Python 버전과 호환되어야 합니다. 현재 저장소는 용량 최적화를 위해 Windows 64-bit Python 3.14 wheel만 포함합니다. 다른 버전/32-bit Python이면 설치하지 말고 Python 3.14 64-bit를 사용하거나 `wheels`를 다시 생성해야 합니다.

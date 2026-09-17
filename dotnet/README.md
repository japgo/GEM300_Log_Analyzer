# GEM300 Log Analyzer — C# / Avalonia Preview

v2.0.0-preview.2는 **분석과 키워드 변경 속도**를 우선한 새 데스크톱 구현입니다. Windows/macOS에서 실행하며, 기존 Python UI는 비교·회귀 검증용으로 보존합니다. 기존 앱 전체 기능의 이전이 완료된 버전은 아닙니다.

## 실행

개발에는 .NET 10 SDK가 필요합니다. Avalonia는 NuGet으로 복원되며 별도 사용자 설치 프로그램은 없습니다.

- macOS: 저장소 루트의 `run_avalonia_mac.command` 실행. 현재 개발 장비에서는 임시 개발용 SDK도 자동 감지합니다. 임시 SDK가 삭제되면 .NET 10 SDK를 설치하거나 `GEM300_DOTNET`에 SDK 실행 파일 경로를 지정하세요.
- Windows 개발: `run_avalonia_windows.cmd` 실행.
- 터미널: `dotnet run --project dotnet/Gem300.Desktop -c Release`.
- 프로그램 사용자 배포: Windows 전용 self-contained 결과 폴더 전체를 ZIP으로 제공합니다. EXE와 함께 제공되는 DLL을 분리하지 마세요. 사용자 PC의 .NET/Avalonia 설치는 필요 없습니다.

## 이번 구현에서 사용 가능한 기능

- MMI/SECS `.log`, `.txt`, `.tslog` 복수 파일 선택, 드래그앤드롭, 실제 분석 파일 목록.
- 메시지 시작 경계 기준 최대 4개 작업자 병렬 파싱. 여러 줄 S6F11 보존. INI 덤프 상태가 있는 MMI는 단일 처리로 전환.
- 파일 경로·크기·수정 시각·파서 버전·INI 옵션별 영구 캐시. 변경된 파일만 다시 분석.
- 분석 시 원문 검색 색인을 동시에 생성. 분석 후 색인 준비를 위한 전체 재읽기 없음.
- 포함 AND/OR, 제외, 대소문자, 정규식, MMI/SECS, SxFy, 날짜·시간 범위 검색. 조건 편집은 실행을 유발하지 않으며 F5 또는 적용 버튼으로 반영.
- 1/2/3문자 블록 색인과 정확한 원문 확인. 키워드별 결과 bitset을 최대 128MB LRU로 재사용하여 조합 변경 시 재검색 최소화.
- 전체 로그/필터 결과 좌우 화면, 별도 컬럼 표시 설정, 페이지당 최대 500행 표시, 결과 선택 시 전체 로그의 같은 위치로 이동.
- 양쪽 로그 클릭 시 하단 원문 표시, 결과 내 F3 이전/F4 다음 찾기(결과 목록 유지), 날짜 표시 옵션.
- 북마크 저장, 북마크만 보기/키워드 예외, 크기 조절 가능한 북마크 창.
- 원문 복사 및 선택한 로그의 주석 포함 복사. 복수 선택 복사 시 ID를 모아 조회.
- 작업 취소, 오류 표시, 정규식 메시지당 100ms 제한, 오래된 선택 조회 결과 폐기.

## DB 주석

분석과 키워드 검색은 DB 서비스를 참조하지 않습니다. `선택 시 주석`이 켜진 경우에만 원문을 먼저 표시하고 선택한 S6F11의 CEID/RPTID를 읽어 DB에서 필요한 이름을 조회합니다. `주석 포함 복사`는 이 옵션과 별도로 명시적 요청으로 동작합니다.

- 기존 SQL Server 스키마 사용: `Events(CEId,Name)`, `ReportVariables(RepId,Index_No,VId)`, `Variables(VId,Name)`.
- CEID 이벤트명, RPTID 식별자, VID 이름을 해당 원문 라인에 붙입니다. RPTID 이름 테이블은 기존 스키마에 없으므로 이름을 임의 조회하지 않습니다.
- 이미 조회한 ID와 없는 ID를 캐시합니다. 서버·DB·인증 설정 변경 시 캐시를 폐기합니다.
- Windows 인증 또는 SQL 인증. 맥에서는 SQL 인증 또는 별도로 구성한 통합 인증 환경이 필요합니다. 암호는 저장하지 않습니다.
- DB 접속/명령 제한 시간, 취소 지원. 실패하면 상세 원문을 유지합니다. 주석 포함 복사가 실패하면 클립보드는 변경하지 않으며 원문 복사 버튼을 사용할 수 있습니다.
- DB가 없는 환경에서도 모든 분석·원문 검색 기능 사용 가능.
- **키워드는 원문 메시지를 검색합니다. CEID/VID의 DB 이름으로 전체 로그를 찾는 기능은 아직 이전하지 않았습니다.** 클릭한 로그의 주석을 검색 인덱스에 섞지 않습니다.

## 성능 구조와 캐시

`Gem300.Core`는 UI/DB 패키지 의존성이 없는 엔진입니다. 파일을 버퍼로 순차 읽고 각 로그의 시간·원문 위치·길이 등은 구조체 배열에 저장합니다. 검색용 정규화 메시지는 디스크 `.text`, 메타데이터와 블록 색인은 `.meta`에 저장합니다. UI 객체는 표시하는 500행에 대해서만 만듭니다.

블록 색인은 없는 문자열이 포함될 수 없는 구간을 제외하는 보수적인 색인입니다. 후보 블록은 큰 단위로 읽고 정확히 비교하므로 오탐은 결과에 포함되지 않습니다. 흔한 문자열이나 복잡한 정규식은 많은 블록을 읽을 수 있습니다. 정규식에는 전체 블록 병렬 검사를 사용합니다.

기본 캐시: `.NET LocalApplicationData/GEM300LogAnalyzer/dotnet-cache`. `GEM300_CACHE_DIR`로 변경할 수 있습니다. 원문 복사/상세 표시에는 원본 파일이 필요하며 분석 후 변경된 파일은 재분석을 안내합니다. 이전 지문의 캐시는 현재 자동 정리하지 않으므로 앱을 종료하고 캐시 폴더를 비우면 재생성됩니다.

## 검증

```sh
dotnet build dotnet/Gem300.Desktop -c Release
dotnet run --project dotnet/Gem300.Checks -c Release
dotnet run --project dotnet/Gem300.Desktop -c Release -- --smoke
dotnet run --project dotnet/Gem300.Checks -c Release -- --benchmark <MMI.log> <SECS.log>
```

`--smoke`는 실제 앱 창을 잠시 띄워 분석, 수동 적용, 좌우 선택, 결과 내 찾기, 상세, 독립 컬럼 설정을 점검하고 종료합니다. 별도 `GEM300_CACHE_DIR`를 지정하여 테스트 설정을 사용자 설정과 분리하세요.

기존 Python 결과와 비교:

```sh
src/.venv/bin/python dotnet/tools/compare_python.py <MMI.log> <SECS.log>
```

검증 결과와 대용량 측정은 `PERFORMANCE.md`에 기록합니다. Windows self-contained 빌드/ZIP 릴리즈는 사용자가 푸시를 요청한 경우 실행되는 GitHub Actions가 담당합니다.

## 후속 이전 범위

기존 Python의 GEM300 흐름도·알람/왕복 분석·로그 비교·보고서 내보내기, 검색 프리셋/세션, CEID 제외 편집, DB 이름으로 검색, 북마크 메모 등은 아직 C# UI로 이전하지 않았습니다. INI 덤프 제외 이외의 로딩 제외 조건은 이번 프리뷰에서 지원하지 않습니다. 기존 설정/북마크 파일을 자동 변환하지 않으며 C# 설정은 별도 저장합니다.

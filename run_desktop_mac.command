#!/bin/bash

set -u

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_ROOT="$PROJECT_ROOT/src"
VENV_ROOT="$APP_ROOT/.venv"
VENV_PYTHON="$VENV_ROOT/bin/python"

fail() {
    echo
    echo "실행 준비에 실패했습니다: $1"
    echo
    if [[ -t 0 ]]; then
        read -r -p "Enter 키를 누르면 창이 닫힙니다..." _
    fi
    exit 1
}

python_is_compatible() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
        >/dev/null 2>&1
}

find_base_python() {
    local candidate
    for candidate in \
        "/opt/homebrew/bin/python3.12" \
        "/usr/local/bin/python3.12" \
        "$(command -v python3 2>/dev/null || true)"
    do
        if [[ -n "$candidate" && -x "$candidate" ]] && python_is_compatible "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

if [[ ! -x "$VENV_PYTHON" ]] || ! python_is_compatible "$VENV_PYTHON"; then
    BASE_PYTHON="$(find_base_python)" || fail \
        "Python 3.11 이상이 필요합니다. Homebrew로 Python 3.12를 설치하세요."

    "$BASE_PYTHON" -c 'import tkinter' >/dev/null 2>&1 || fail \
        "Tkinter가 필요합니다. 터미널에서 'brew install python-tk@3.12'를 실행하세요."

    echo "macOS용 Python 가상환경을 준비합니다..."
    "$BASE_PYTHON" -m venv --clear "$VENV_ROOT" || fail \
        "가상환경을 만들 수 없습니다."
fi

if ! "$VENV_PYTHON" -c \
    'import gem300_log_analyzer, pandas, pyodbc, streamlit, tkinter, tkinterdnd2, yaml' \
    >/dev/null 2>&1
then
    echo "처음 실행에 필요한 패키지를 설치합니다..."
    "$VENV_PYTHON" -m pip install --upgrade pip || fail \
        "pip 업그레이드에 실패했습니다. 인터넷 연결을 확인하세요."
    "$VENV_PYTHON" -m pip install -e "$APP_ROOT" || fail \
        "패키지 설치에 실패했습니다. pyodbc 오류라면 'brew install unixodbc'를 실행하세요."
fi

"$VENV_PYTHON" -c 'import tkinter; import pyodbc' >/dev/null 2>&1 || fail \
    "macOS 런타임을 불러올 수 없습니다. 'brew install python-tk@3.12 unixodbc'를 실행하세요."

if [[ "${1:-}" == "--check" ]]; then
    echo "macOS 실행 환경 확인 완료: $($VENV_PYTHON --version 2>&1)"
    exit 0
fi

cd "$APP_ROOT" || fail "앱 폴더를 열 수 없습니다."
exec "$VENV_PYTHON" desktop_app.py

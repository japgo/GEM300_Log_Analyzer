@echo off
setlocal

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\run_desktop.ps1"

if errorlevel 1 (
    echo.
    echo GEM300 Log Analyzer failed to start.
    pause
)


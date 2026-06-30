@echo off
setlocal

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\tools\install_offline.ps1"

if errorlevel 1 (
    echo.
    echo GEM300 Log Analyzer offline install failed.
    pause
)

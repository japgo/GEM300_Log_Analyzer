@echo off
setlocal

cd /d "%~dp0"
wscript.exe "%~dp0src\run_desktop.vbs"

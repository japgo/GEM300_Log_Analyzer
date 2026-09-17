@echo off
cd /d "%~dp0dotnet"
dotnet run --project Gem300.Desktop -c Release -- %*
if errorlevel 1 pause

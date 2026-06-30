# GEM300 Log Analyzer Offline Install

This package is for PCs without internet access.

## Assumptions

- Python is already installed on the target PC and available as `py` or `python`.
- SQL Server ODBC Driver is already installed on the target PC.
- This installer does not include or run Python installers.
- This installer does not include or run ODBC Driver installers.

## Install

Open PowerShell in this package folder and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install_offline.ps1 -CreateDesktopShortcut
```

If Python is not on PATH, pass the executable explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install_offline.ps1 -PythonCommand "C:\Path\To\python.exe" -CreateDesktopShortcut
```

## Run

After install:

```powershell
.\app\run_desktop.bat
```

or use the desktop shortcut if it was created.

# GEM300 Log Analyzer Offline Install

This repository is arranged so a user can `git pull`, install, and run without internet access.

## Root folder

```text
src
wheels
offline_install.bat
run_desktop.bat
```

## Assumptions

- Windows 64-bit Python 3.14 is already installed on the target PC and available as `py` or `python`.
- SQL Server ODBC Driver is already installed on the target PC.
- This installer does not include or run Python installers.
- This installer does not include or run ODBC Driver installers.

## Install

Run this from the repository root:

```bat
offline_install.bat
```

The installer creates `src\.venv` and installs packages only from the root `wheels` folder.

## Run

After install, run this from the repository root:

```bat
run_desktop.bat
```

## Python version note

Wheel files must match the target PC Python version and platform. This repository is size-optimized and includes Windows 64-bit wheels for Python 3.14 only. Use Python 3.14 64-bit or rebuild `wheels` for another Python version.



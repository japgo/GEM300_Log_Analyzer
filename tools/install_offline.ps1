param(
    [string]$PythonCommand = "",
    [switch]$CreateDesktopShortcut
)

$ErrorActionPreference = "Stop"

$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppRoot = Join-Path $PackageRoot "app"
$WheelsRoot = Join-Path $PackageRoot "wheels"
$VenvRoot = Join-Path $AppRoot ".venv"
$Requirements = Join-Path $AppRoot "requirements.txt"

if (-not (Test-Path $AppRoot)) {
    throw "App folder not found: $AppRoot"
}
if (-not (Test-Path $WheelsRoot)) {
    throw "Wheelhouse folder not found: $WheelsRoot"
}
if (-not (Test-Path $Requirements)) {
    throw "requirements.txt not found: $Requirements"
}

function Resolve-PythonCommand {
    param([string]$Preferred)
    if ($Preferred) {
        return $Preferred
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py"
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }
    throw "Python is not available in PATH. Install Python first or pass -PythonCommand."
}

$Python = Resolve-PythonCommand $PythonCommand

Push-Location $AppRoot
try {
    if (-not (Test-Path $VenvRoot)) {
        & $Python -m venv $VenvRoot
    }

    $VenvPython = Join-Path $VenvRoot "Scripts\python.exe"
    if (-not (Test-Path $VenvPython)) {
        throw "Virtual environment Python not found: $VenvPython"
    }

    & $VenvPython -m pip install --no-index --find-links $WheelsRoot -r $Requirements
}
finally {
    Pop-Location
}

if ($CreateDesktopShortcut) {
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $ShortcutPath = Join-Path $Desktop "GEM300 Log Analyzer.lnk"
    $Target = Join-Path $AppRoot "run_desktop_hidden.vbs"
    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $Target
    $Shortcut.WorkingDirectory = $AppRoot
    $IconPath = Join-Path $AppRoot "assets\app_icon.ico"
    if (Test-Path $IconPath) {
        $Shortcut.IconLocation = $IconPath
    }
    $Shortcut.Save()
}

Write-Host "Offline install completed."
Write-Host "Run: $AppRoot\run_desktop.bat"
Write-Host "Python and ODBC driver installers are not included or executed by this installer."

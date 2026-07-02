$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $Root
$PythonExe = Join-Path $Root ".venv\Scripts\python.exe"
$WheelsDir = Join-Path $RepoRoot "wheels"
$Icon = Join-Path $Root "assets\app_icon.ico"
$Assets = Join-Path $Root "assets"
$Config = Join-Path $Root "config"
$DistPath = Join-Path $Root "dist"
$WorkPath = Join-Path $Root "build\work"
$SpecPath = Join-Path $Root "build"
$VersionFile = Join-Path $Root "gem300_log_analyzer\__init__.py"
$VersionText = Get-Content -LiteralPath $VersionFile -Raw
if ($VersionText -notmatch "__version__\s*=\s*`"([^`"]+)`"") {
    throw "Could not read app version from $VersionFile"
}
$AppName = "GEM300_Log_Analyzer_v$($Matches[1])"

if (-not (Test-Path $PythonExe)) {
    throw "Virtual environment was not found. Run offline_install.bat first."
}

& $PythonExe -m pip install --no-index --find-links $WheelsDir pyinstaller

& $PythonExe -m PyInstaller `
    --noconfirm `
    --clean `
    --windowed `
    --onefile `
    --name $AppName `
    --icon $Icon `
    --paths $Root `
    --add-data "$Assets;assets" `
    --add-data "$Config;config" `
    --collect-all tkinterdnd2 `
    --hidden-import pyodbc `
    --distpath $DistPath `
    --workpath $WorkPath `
    --specpath $SpecPath `
    (Join-Path $Root "desktop_app.py")

Write-Host "Built EXE: $(Join-Path $DistPath ($AppName + '.exe'))"

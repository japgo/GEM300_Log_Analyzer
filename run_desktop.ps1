$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $Root ".venv\Scripts\python.exe"
$WheelsDir = Join-Path (Split-Path -Parent $Root) "wheels"

if (-not (Test-Path $PythonExe)) {
    Write-Host "Virtual environment was not found. Creating .venv..."
    py -3.11 -m venv (Join-Path $Root ".venv")
    if (Test-Path $WheelsDir) {
        & $PythonExe -m pip install --no-index --find-links $WheelsDir -r (Join-Path $Root "requirements.txt")
    }
    else {
        & $PythonExe -m pip install -r (Join-Path $Root "requirements.txt")
    }
}

Push-Location $Root
try {
    & $PythonExe desktop_app.py
}
finally {
    Pop-Location
}

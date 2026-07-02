$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $Root ".venv\Scripts\python.exe"
$PythonwExe = Join-Path $Root ".venv\Scripts\pythonw.exe"
$WheelsDir = Join-Path (Split-Path -Parent $Root) "wheels"
$Requirements = Join-Path $Root "requirements.txt"

function Resolve-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py"
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }
    throw "Python is not available in PATH. Install Python first."
}

if (-not (Test-Path $PythonExe)) {
    if (-not (Test-Path $WheelsDir)) {
        throw "Offline wheelhouse was not found: $WheelsDir"
    }
    Write-Host "Virtual environment was not found. Creating .venv with installed Python..."
    $PythonCommand = Resolve-PythonCommand
    & $PythonCommand -m venv (Join-Path $Root ".venv")
    & $PythonExe -m pip install --no-index --find-links $WheelsDir -r $Requirements
}

Push-Location $Root
try {
    $AppPythonExe = if (Test-Path $PythonwExe) { $PythonwExe } else { $PythonExe }
    & $AppPythonExe desktop_app.py
}
finally {
    Pop-Location
}

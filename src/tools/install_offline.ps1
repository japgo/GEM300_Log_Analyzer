param(
    [string]$PythonCommand = "",
    [switch]$CreateDesktopShortcut
)

$ErrorActionPreference = "Stop"

$ToolsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppRoot = Split-Path -Parent $ToolsRoot
$PackageRoot = Split-Path -Parent $AppRoot
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
function Get-PythonRuntimeInfo {
    param([string]$PythonExe)
    $code = "import struct,sys; print(str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'|cp'+str(sys.version_info.major)+str(sys.version_info.minor)+'|'+str(struct.calcsize('P')*8))"
    $info = & $PythonExe -c $code
    if ($LASTEXITCODE -ne 0 -or -not $info) {
        throw "Failed to read Python runtime information from: $PythonExe"
    }
    $parts = $info.Trim().Split("|")
    if ($parts.Count -ne 3) {
        throw "Unexpected Python runtime information: $info"
    }
    [pscustomobject]@{
        Version = $parts[0]
        AbiTag = $parts[1]
        Bits = [int]$parts[2]
    }
}

function Assert-CompatibleWheelhouse {
    param(
        [string]$PythonExe,
        [string]$WheelsPath
    )
    $runtime = Get-PythonRuntimeInfo $PythonExe
    if ($runtime.Bits -ne 64) {
        throw "Unsupported Python runtime: $($runtime.Version) $($runtime.Bits)-bit. This offline package contains Windows 64-bit Python 3.14 wheels only."
    }
    if ($runtime.Version -ne "3.14") {
        throw "Unsupported Python version: $($runtime.Version). This offline package is optimized for Windows 64-bit Python 3.14 only."
    }
    $pandasWheel = Get-ChildItem -LiteralPath $WheelsPath -File -Filter "pandas-*.whl" |
        Where-Object { $_.Name -like "*$($runtime.AbiTag)*win_amd64.whl" -or $_.Name -like "*py3-none-any.whl" } |
        Select-Object -First 1
    if (-not $pandasWheel) {
        $availableTags = Get-ChildItem -LiteralPath $WheelsPath -File -Filter "pandas-*.whl" |
            ForEach-Object {
                if ($_.Name -match "-(cp\d+)-") { $matches[1] }
            } |
            Sort-Object -Unique
        throw "No compatible pandas wheel for Python $($runtime.Version) ($($runtime.AbiTag)) in $WheelsPath. Available pandas wheel tags: $($availableTags -join ', '). Use Windows 64-bit Python 3.14 or rebuild wheels for this Python version."
    }
    Write-Host "Python runtime: $($runtime.Version) $($runtime.Bits)-bit ($($runtime.AbiTag))"
    Write-Host "Compatible pandas wheel: $($pandasWheel.Name)"
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

    Assert-CompatibleWheelhouse -PythonExe $VenvPython -WheelsPath $WheelsRoot
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
Write-Host "Run: $PackageRoot\run_desktop.bat"
Write-Host "Python and ODBC driver installers are not included or executed by this installer."



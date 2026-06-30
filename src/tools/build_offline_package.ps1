param(
    [string]$OutputRoot = "dist_offline",
    [string]$PackageName = "GEM300_Log_Analyzer_Offline",
    [string]$PythonCommand = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$PackageRoot = Join-Path $RepoRoot $OutputRoot
$TargetRoot = Join-Path $PackageRoot $PackageName
$AppRoot = Join-Path $TargetRoot "app"
$WheelsRoot = Join-Path $TargetRoot "wheels"

if (Test-Path $TargetRoot) {
    Remove-Item -LiteralPath $TargetRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $AppRoot, $WheelsRoot | Out-Null

$excludeDirs = @(".git", ".venv", "dist", "dist_offline", "build", "__pycache__", ".pytest_cache")
$excludeFiles = @(".DS_Store", "*.pyc", "*.pyo")

Get-ChildItem -LiteralPath $RepoRoot -Force | Where-Object {
    $excludeDirs -notcontains $_.Name -and
    $_.Name -ne $OutputRoot -and
    $_.Name -ne $PackageName
} | ForEach-Object {
    $destination = Join-Path $AppRoot $_.Name
    if ($_.PSIsContainer) {
        Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force -Exclude $excludeFiles
    }
    else {
        if ($_.Name -notlike ".DS_Store") {
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }
    }
}

if ($PythonCommand) {
    & $PythonCommand -m pip download -r (Join-Path $RepoRoot "src\requirements.txt") -d $WheelsRoot
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -m pip download -r (Join-Path $RepoRoot "src\requirements.txt") -d $WheelsRoot
}
else {
    & python -m pip download -r (Join-Path $RepoRoot "src\requirements.txt") -d $WheelsRoot
}

Copy-Item -LiteralPath (Join-Path $RepoRoot "src\tools\install_offline.ps1") -Destination (Join-Path $TargetRoot "install_offline.ps1") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "src\tools\README_OFFLINE_INSTALL.md") -Destination (Join-Path $TargetRoot "README_INSTALL.md") -Force

Write-Host "Offline package created: $TargetRoot"
Write-Host "Python installer and ODBC driver installer are intentionally NOT included."

